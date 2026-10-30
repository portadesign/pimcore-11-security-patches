<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115894')]
final class TwigSandboxTest extends \PHPUnit\Framework\TestCase
{
    private \Pimcore\Templating\TwigDefaultDelegatingEngine $engine;

    protected function setUp(): void
    {
        $engine = \Pimcore::getContainer()->get('pimcore.templating.engine.delegating');
        \assert($engine instanceof \Pimcore\Templating\TwigDefaultDelegatingEngine);
        $this->engine = $engine;
    }

    protected function tearDown(): void
    {
        $this->engine->disableSandboxExtensionFromTwigEnvironment();
    }

    /**
     * @return array<string, array{string, class-string<\Twig\Sandbox\SecurityError>}>
     */
    public static function blockedTemplateProvider(): array
    {
        return [
            'user password getter' => ['{{ user.getPassword() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user password through attribute access' => ['{{ user.password }}', \Twig\Sandbox\SecurityNotAllowedPropertyError::class],
            'user recovery token' => ['{{ user.getPasswordRecoveryToken() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user two factor secret' => ['{{ user.getTwoFactorAuthentication() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user harmless getter' => ['{{ user.getName() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset binary data' => ['{{ asset.getData() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset stream' => ['{{ asset.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset local file' => ['{{ asset.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset temporary file' => ['{{ asset.getTemporaryFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection query' => ["{{ db.fetchOne('SELECT 1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection property' => ['{{ db.params }}', \Twig\Sandbox\SecurityNotAllowedPropertyError::class],
            'service container' => ["{{ container.get('kernel') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'pimcore user function' => ['{{ pimcore_user(1) }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
            'pimcore user function chained' => ['{{ pimcore_user(1).getPassword() }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
        ];
    }

    /**
     * @param class-string<\Twig\Sandbox\SecurityError> $expectedError
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('blockedTemplateProvider')]
    public function testSandboxedTemplateIsBlocked(string $template, string $expectedError): void
    {
        $this->expectException($expectedError);

        $this->render($template);
    }

    public function testSandboxedTemplateRendersHarmlessContent(): void
    {
        $asset = new \Pimcore\Model\Asset\Folder();
        $asset->setFilename('report.txt');

        $rendered = $this->render(
            '{% set greeting = "Hello" %}{{ greeting }} {{ name|escape }}, {{ asset.getFilename() }}',
            ['name' => '<b>World</b>', 'asset' => $asset],
        );

        $this->assertSame('Hello &lt;b&gt;World&lt;/b&gt;, report.txt', $rendered);
    }

    public function testMailSubjectRenderingBlocksPasswordLeak(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setPassword('hash-123');

        $mail = new \Pimcore\Mail();
        $mail->setParam('user', $user);
        $mail->subject('Reset {{ user.getPassword() }}');

        try {
            $rendered = $mail->getSubjectRendered();
        } catch (\TypeError $e) {
            // 11.5.14.1 names the template pimcore_email_subject but still cuts the message at ' in "__string', so substr() gets false
            $this->assertStringContainsString('substr(): Argument #3', $e->getMessage());

            return;
        } catch (\Exception $e) {
            $this->assertMatchesRegularExpression('/^Failed rendering the subject: Calling method "getPassword" on "Pimcore\\\\Model\\\\User" is not allowed in templates\./', $e->getMessage());

            return;
        }

        $this->fail('Subject rendered without a sandbox error: ' . $rendered);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function render(string $template, array $context = []): string
    {
        $user = new \Pimcore\Model\User();
        $user->setName('admin');
        $user->setPassword('hash-123');

        $defaults = [
            'user' => $user,
            'asset' => new \Pimcore\Model\Asset\Text(),
            'db' => \Pimcore\Db::get(),
            'container' => \Pimcore::getContainer(),
        ];

        $twig = $this->engine->getTwigEnvironment(true);

        return $twig->createTemplate($template)->render(array_merge($defaults, $context));
    }
}
