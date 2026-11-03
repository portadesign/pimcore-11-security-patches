<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxMutatorTest extends \PHPUnit\Framework\TestCase
{
    private \Pimcore\Templating\TwigDefaultDelegatingEngine $engine;

    private \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage $tokenStorage;

    private \Symfony\Component\HttpFoundation\RequestStack $requestStack;

    private \Symfony\Bridge\Twig\AppVariable $app;

    protected function setUp(): void
    {
        $engine = \Pimcore::getContainer()->get('pimcore.templating.engine.delegating');
        \assert($engine instanceof \Pimcore\Templating\TwigDefaultDelegatingEngine);
        $this->engine = $engine;

        $this->tokenStorage = new \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage();
        $this->requestStack = new \Symfony\Component\HttpFoundation\RequestStack();
        $this->app = new \Symfony\Bridge\Twig\AppVariable();
        $this->app->setTokenStorage($this->tokenStorage);
        $this->app->setRequestStack($this->requestStack);
    }

    protected function tearDown(): void
    {
        $this->engine->disableSandboxExtensionFromTwigEnvironment();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function elementMutatorProvider(): array
    {
        return [
            'save' => ['{{ element.save() }}', 'save'],
            'delete' => ['{{ element.delete() }}', 'delete'],
            'setter' => ["{% set changed = element.setFilename('hacked') %}", 'setFilename'],
            'bulk setter' => ["{% set changed = element.setValues({'filename': 'hacked'}) %}", 'setValues'],
            'generic setter' => ["{% set changed = element.setValue('filename', 'hacked') %}", 'setValue'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('elementMutatorProvider')]
    public function testElementMutatorIsBlocked(string $template, string $method): void
    {
        $element = $this->createMock(\Pimcore\Model\Asset\Folder::class);
        $element->expects($this->never())->method($method);

        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->render($template, ['element' => $element]);
    }

    public function testElementMutatorLeavesElementUntouched(): void
    {
        $element = new \Pimcore\Model\Asset\Folder();
        $element->setFilename('original');

        try {
            $this->render("{% set changed = element.setFilename('hacked') %}", ['element' => $element]);
            $this->fail('Mutator was not rejected');
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
            $this->assertSame('original', $element->getFilename());
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function daoDelegatedMutatorProvider(): array
    {
        return [
            'update' => ['updateChildPaths'],
            'delete' => ['deleteAllProperties'],
            'lock' => ['lock'],
            'permission sql' => ['isInheritingPermission'],
            'create' => ['create'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('daoDelegatedMutatorProvider')]
    public function testDaoDelegatedMutatorIsBlocked(string $method): void
    {
        $element = new class () extends \Pimcore\Model\Asset\Folder {
            /**
             * @var string[]
             */
            public array $delegated = [];

            public function __call(string $method, array $args): mixed
            {
                $this->delegated[] = $method;

                return null;
            }
        };

        try {
            $this->render('{% set changed = element.' . $method . '() %}', ['element' => $element]);
            $this->fail('Mutator was not rejected');
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
            $this->assertSame([], $element->delegated);
        }
    }

    public function testHardBlockedMethodsHoldForAllowedClasses(): void
    {
        $container = \Pimcore::getContainer();
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy(
            blockedClasses: $container->getParameter('pimcore.templating.twig.sandbox_security_policy.blocked_classes'),
            allowedClasses: [\Pimcore\Model\User::class, \Pimcore\Model\DataObject\ClassDefinition::class],
            hardBlockedMethods: $container->getParameter('pimcore.templating.twig.sandbox_security_policy.hard_blocked_methods'),
        );
        $user = new \Pimcore\Model\User();

        $policy->checkMethodAllowed($user, 'getName');

        foreach (['getPassword', 'getPasswordRecoveryToken', 'setPassword', 'save', 'delete'] as $method) {
            try {
                $policy->checkMethodAllowed($user, $method);
                $this->fail($method . ' was not rejected');
            } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
                $this->addToAssertionCount(1);
            }
        }

        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $policy->checkMethodAllowed(new \Pimcore\Model\DataObject\ClassDefinition(), 'save');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function classDefinitionProvider(): array
    {
        return [
            'class description' => ["{% set changed = definition.setDescription('**// system(\$_GET[0]); /*') %}"],
            'class getter' => ['{{ definition.getFieldDefinitions() }}'],
            'brick definition' => ["{% set changed = brick.setKey('x') %}"],
            'fieldcollection definition' => ["{% set changed = collection.setKey('x') %}"],
            'custom layout' => ["{% set changed = customLayout.setDescription('x') %}"],
            'field definition' => ["{% set changed = field.setName('x') %}"],
            'layout definition' => ["{% set changed = layout.setName('x') %}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('classDefinitionProvider')]
    public function testClassDefinitionIsBlocked(string $template): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->render($template, [
            'definition' => new \Pimcore\Model\DataObject\ClassDefinition(),
            'brick' => new \Pimcore\Model\DataObject\Objectbrick\Definition(),
            'collection' => new \Pimcore\Model\DataObject\Fieldcollection\Definition(),
            'customLayout' => new \Pimcore\Model\DataObject\ClassDefinition\CustomLayout(),
            'field' => new \Pimcore\Model\DataObject\ClassDefinition\Data\Input(),
            'layout' => new \Pimcore\Model\DataObject\ClassDefinition\Layout\Panel(),
        ]);
    }

    public function testClassDefinitionStaysUntouched(): void
    {
        $definition = new \Pimcore\Model\DataObject\ClassDefinition();

        try {
            $this->render("{% set changed = definition.setDescription('changed') %}", ['definition' => $definition]);
            $this->fail('Mutator was not rejected');
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
            $this->assertNotSame('changed', $definition->getDescription());
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function applicationVariableProvider(): array
    {
        return [
            'user password property' => ['{{ app.user.password }}'],
            'user password getter' => ['{{ app.user.getPassword() }}'],
            'security token user' => ['{{ app.token.getUser().getPassword() }}'],
            'session' => ["{{ app.session.get('secret') }}"],
            'cookies' => ["{{ app.request.cookies.get('sid') }}"],
            'request headers' => ["{{ app.request.headers.get('authorization') }}"],
            'request attributes' => ["{{ app.request.attributes.get('secret') }}"],
            'request basic auth password' => ['{{ app.request.getPassword() }}'],
            'request string cast' => ['{{ app.request }}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('applicationVariableProvider')]
    public function testApplicationVariableLeakIsBlocked(string $template): void
    {
        $this->authenticate(new \Symfony\Component\Security\Core\User\InMemoryUser('sender', 'secret-hash'));
        $this->pushRequest();

        $this->expectException(\Twig\Sandbox\SecurityError::class);

        $this->render($template);
    }

    public function testAdminUserWrapperLeakIsBlocked(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setName('sender');
        $user->setPassword('secret-hash');
        $this->authenticate(new \Pimcore\Security\User\User($user));

        $this->expectException(\Twig\Sandbox\SecurityError::class);

        $this->render('{{ app.user.user.getPassword() }}');
    }

    public function testAdminUserTwoFactorSecretIsBlocked(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setName('sender');
        $this->authenticate(new \Pimcore\Security\User\User($user));

        $this->expectException(\Twig\Sandbox\SecurityError::class);

        $this->render('{{ app.user.getGoogleAuthenticatorSecret() }}');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function blockedFunctionProvider(): array
    {
        return [
            'dump' => ["{{ pimcore_dump('value') }}"],
            'file exists' => ["{{ pimcore_file_exists('/etc/hostname') }}"],
            'include' => ["{{ pimcore_inc('/') }}"],
            'website config' => ["{{ pimcore_website_config('key') }}"],
            'renderlet' => ["{{ pimcore_renderlet('item', {'controller': 'App\\\\Controller::action'}) }}"],
            'snippet' => ["{{ pimcore_snippet('item') }}"],
            'asset version preview' => ["{{ pimcore_asset_version_preview('/nonexistent') }}"],
            'image version preview' => ["{{ pimcore_image_version_preview('/nonexistent') }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('blockedFunctionProvider')]
    public function testPimcoreFunctionIsBlocked(string $template): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedFunctionError::class);

        $this->render($template);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function fileConsumingFunctionProvider(): array
    {
        return [
            'asset version preview' => ['pimcore_asset_version_preview'],
            'image version preview' => ['pimcore_image_version_preview'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('fileConsumingFunctionProvider')]
    public function testFileConsumingFunctionLeavesFileUntouched(string $function): void
    {
        $file = tempnam(sys_get_temp_dir(), 'pd-sec-');
        $this->assertIsString($file);
        file_put_contents($file, 'sentinel');

        try {
            $this->render('{{ ' . $function . '(file) }}', ['file' => $file]);
            $this->fail('Function was not rejected');
        } catch (\Twig\Sandbox\SecurityNotAllowedFunctionError) {
            $this->assertSame('sentinel', file_get_contents($file));
        } finally {
            @unlink($file);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function staticMethodProvider(): array
    {
        return [
            'document list' => ["{% set found = element.getList({'limit': 1}) %}"],
            'document list with listing class' => ["{% set found = element.getList({'condition': '1=1', 'class': 'Pimcore\\\\Model\\\\User\\\\Listing'}) %}"],
            'document by id' => ['{% set found = element.getById(1) %}'],
            'document by path' => ["{% set found = element.getByPath('/') %}"],
            'oracle in list' => ["{{ element in element.getList({'limit': 1}) }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('staticMethodProvider')]
    public function testStaticMethodOnInstanceIsBlocked(string $template): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->render($template, ['element' => new \Pimcore\Model\Document\Folder()]);
    }

    public function testUndeclaredModelMethodIsBlocked(): void
    {
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy();
        $element = new \Pimcore\Model\Document\Folder();

        $policy->checkMethodAllowed($element, 'getKey');
        $this->addToAssertionCount(1);

        foreach (['isInheritingPermission', 'noSuchMethod', 'GETLIST'] as $method) {
            try {
                $policy->checkMethodAllowed($element, $method);
                $this->fail($method . ' was not rejected');
            } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testCallMagicOnNonModelObjectStaysAllowed(): void
    {
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy();
        $object = new class () {
            public function __call(string $method, array $args): string
            {
                return $method;
            }
        };

        $policy->checkMethodAllowed($object, 'anything');

        $this->addToAssertionCount(1);
    }

    public function testPermissionSqlInjectionThroughDaoIsBlocked(): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->render("{{ element.isInheritingPermission('view', ['1) OR (1=1']) }}", ['element' => new \Pimcore\Model\Document\Folder()]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function objectTypeInjectionProvider(): array
    {
        return [
            'has children' => ["{{ folder.hasChildren(payload) ? 'y' : 'n' }}|{{ folder.hasChildren(['unknown']) ? 'y' : 'n' }}"],
            'has siblings' => ["{{ folder.hasSiblings(payload) ? 'y' : 'n' }}|{{ folder.hasSiblings(['unknown']) ? 'y' : 'n' }}"],
            'children listing' => ["{{ folder in folder.getChildren(payload) ? 'y' : 'n' }}|{{ folder in folder.getChildren(['unknown']) ? 'y' : 'n' }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('objectTypeInjectionProvider')]
    public function testObjectTypeInjectionYieldsNoOracle(string $template): void
    {
        $folder = new \Pimcore\Model\DataObject\Folder();
        $folder->setId(1);
        $folder->setParentId(1);

        try {
            $rendered = $this->render($template, ['folder' => $folder, 'payload' => ["x') AND ("]]);
        } catch (\Twig\Sandbox\SecurityError) {
            $this->addToAssertionCount(1);

            return;
        }

        [$injected, $harmless] = explode('|', $rendered);
        $this->assertSame($harmless, $injected);
        $this->assertSame('n', $injected);
    }

    public function testInjectedObjectTypeNeverReachesDaoSql(): void
    {
        $payload = ["x') AND (SELECT injected) AND ('1"];
        $statements = [];

        $connection = $this->createStub(\Doctrine\DBAL\Connection::class);
        $connection->method('fetchOne')->willReturnCallback(static function (string $sql) use (&$statements): int {
            $statements[] = $sql;

            return 0;
        });

        $folder = new \Pimcore\Model\DataObject\Folder();
        $folder->setId(1);
        $folder->setParentId(1);
        $dao = $folder->getDao();
        $dao->db = $connection;

        $dao->hasChildren($payload);
        $dao->hasSiblings($payload);
        $dao->getChildAmount($payload);

        $this->assertCount(3, $statements);
        $this->assertStringNotContainsString('injected', implode("\n", $statements));
        $this->assertSame(3, substr_count(implode("\n", $statements), "IN ('')"));
    }

    public function testInjectedObjectTypeNeverReachesListingSql(): void
    {
        $listing = new \Pimcore\Model\DataObject\Listing();
        $listing->setObjectTypes(["x') AND (SELECT injected) AND ('1", \Pimcore\Model\DataObject::OBJECT_TYPE_FOLDER]);

        $sql = $listing->getDao()->getQueryBuilder('o_id')->getSQL();

        $this->assertStringNotContainsString('injected', $sql);
        $this->assertStringContainsString("'folder'", $sql);

        $none = new \Pimcore\Model\DataObject\Listing();
        $none->setObjectTypes(['unknown']);

        $this->assertStringContainsString("type IN ('')", $none->getDao()->getQueryBuilder('o_id')->getSQL());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function arrayThumbnailProvider(): array
    {
        $config = "{'items': [{'method': 'addOverlay', 'arguments': {'image': '../../../../etc/hostname'}}]}";

        return [
            'method with array config' => ['{% set thumbnail = asset.getThumbnail(' . $config . ') %}'],
            'method with legacy array config' => ["{% set thumbnail = asset.getThumbnail({'width': 100}) %}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('arrayThumbnailProvider')]
    public function testArrayThumbnailConfigIsBlocked(string $template): void
    {
        $this->expectException(\Twig\Sandbox\SecurityError::class);

        $this->render($template, ['asset' => new \Pimcore\Model\Asset\Image()]);
    }

    public function testNamedAndDefaultThumbnailConfigsStayAllowed(): void
    {
        $rendered = $this->render(
            "{% set named = asset.getThumbnail('pimcore-system-treepreview') %}{% set default = asset.getThumbnail() %}{{ named.getConfig().getName() }}",
            ['asset' => new \Pimcore\Model\Asset\Image()],
        );

        $this->assertSame('pimcore-system-treepreview', $rendered);
    }

    public function testArrayThumbnailConfigStaysAllowedOutsideSandbox(): void
    {
        $config = \Pimcore\Model\Asset\Image\Thumbnail\Config::getByAutoDetect(['width' => 100]);

        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $config);
    }

    public function testHarmlessRenderingStillWorks(): void
    {
        $folder = new \Pimcore\Model\Asset\Folder();
        $folder->setFilename('report');
        $this->pushRequest();

        $rendered = $this->render(
            '{{ element.getFilename() }}|{{ element.getType() }}|{{ app.request.getPathInfo() }}|{{ app.request.getLocale() }}',
            ['element' => $folder],
        );

        $this->assertSame('report|folder|/mail|en', $rendered);
    }

    private function authenticate(\Symfony\Component\Security\Core\User\UserInterface $user): void
    {
        $this->tokenStorage->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken($user, 'main', []));
    }

    private function pushRequest(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create('/mail', 'GET', [], ['sid' => 'session-cookie'], [], ['PHP_AUTH_USER' => 'basic', 'PHP_AUTH_PW' => 'basic-secret', 'HTTP_AUTHORIZATION' => 'Bearer token']);
        $request->attributes->set('secret', 'attribute-secret');
        $request->setLocale('en');

        $session = new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage());
        $session->set('secret', 'session-secret');
        $request->setSession($session);

        $this->requestStack->push($request);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function render(string $template, array $context = []): string
    {
        return $this->engine->getTwigEnvironment(true)->createTemplate($template)->render(array_merge(['app' => $this->app], $context));
    }
}
