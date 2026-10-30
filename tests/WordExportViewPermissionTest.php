<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45703')]
final class WordExportViewPermissionTest extends \PHPUnit\Framework\TestCase
{
    private const USERNAME = 'pd-sec-wordexport-user';

    private const PAGE_KEY = 'pd-sec-wordexport-page';

    private const PAGE_TITLE = 'pd-sec-wordexport-title';

    private const EXPORT_ID = 'pdsecwordexport';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\Document\Page $page;

    protected function setUp(): void
    {
        $this->removeFixtures();

        $this->page = new \Pimcore\Model\Document\Page();
        $this->page->setParentId(1);
        $this->page->setKey(self::PAGE_KEY);
        $this->page->setTitle(self::PAGE_TITLE);
        $this->page->setController(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::class . '::renderAction');
        $this->page->setPublished(true);
        $this->page->save();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash('not-used', PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['word_export', 'documents']);
        $this->user->save();

        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->tokenStorage()->setToken(null);
        $this->removeFixtures();
    }

    public function testElementWithoutViewPermissionIsNotExported(): void
    {
        $response = $this->export([['type' => 'document', 'id' => $this->page->getId()]]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $this->exportedHtml());
    }

    public function testElementWithViewPermissionIsExported(): void
    {
        $this->grantView($this->page);

        $response = $this->export([['type' => 'document', 'id' => $this->page->getId()]]);

        $this->assertSame(200, $response->getStatusCode());
        $html = $this->exportedHtml();
        $this->assertStringContainsString('(ID: ' . $this->page->getId() . ')', $html);
        $this->assertStringContainsString(self::PAGE_TITLE, $html);
        $this->assertStringContainsString(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::BODY, $html);
    }

    public function testUnknownElementIsSkipped(): void
    {
        $response = $this->export([['type' => 'document', 'id' => 0]]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $this->exportedHtml());
    }

    public function testUserWithoutWordExportPermissionIsDenied(): void
    {
        $this->user->setPermissions(['documents']);
        $this->user->save();
        $this->authenticate($this->user);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->export([['type' => 'document', 'id' => $this->page->getId()]]);
    }

    /**
     * @param list<array{type: string, id: int}> $elements
     */
    private function export(array $elements): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: [
            'id' => self::EXPORT_ID,
            'data' => json_encode($elements, JSON_THROW_ON_ERROR),
            'source' => 'en',
        ]);
        $request->setMethod('POST');

        return $this->controller()->wordExportAction($request, new \Symfony\Component\Filesystem\Filesystem());
    }

    private function controller(): \Pimcore\Bundle\WordExportBundle\Controller\TranslationController
    {
        $container = \Pimcore::getContainer();

        if ($container->has(\Pimcore\Bundle\WordExportBundle\Controller\TranslationController::class)) {
            return $container->get(\Pimcore\Bundle\WordExportBundle\Controller\TranslationController::class);
        }

        $controller = new \Pimcore\Bundle\WordExportBundle\Controller\TranslationController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    private function exportedHtml(): string
    {
        $file = $this->exportFile();

        return is_file($file) ? (string) file_get_contents($file) : '';
    }

    private function exportFile(): string
    {
        return PIMCORE_SYSTEM_TEMP_DIRECTORY . DIRECTORY_SEPARATOR . self::EXPORT_ID . '.html';
    }

    private function grantView(\Pimcore\Model\Document $document): void
    {
        $workspace = new \Pimcore\Model\User\Workspace\Document();
        $workspace->setCid($document->getId());
        $workspace->setCpath($document->getRealFullPath());
        $workspace->setView(true);

        $this->user->setWorkspacesDocument([$workspace]);
        $this->user->save();
        $this->authenticate($this->user);
    }

    private function authenticate(\Pimcore\Model\User $user): void
    {
        $this->tokenStorage()->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
            new \Pimcore\Security\User\User($user),
            'pimcore_admin',
            [],
        ));
    }

    private function tokenStorage(): \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
    {
        $resolver = \Pimcore::getContainer()->get(\Pimcore\Security\User\TokenStorageUserResolver::class);

        return (new \ReflectionProperty($resolver, 'tokenStorage'))->getValue($resolver);
    }

    private function removeFixtures(): void
    {
        @unlink($this->exportFile());

        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }

        $page = \Pimcore\Model\Document::getByPath('/' . self::PAGE_KEY);

        if ($page instanceof \Pimcore\Model\Document) {
            $page->delete();
        }
    }
}
