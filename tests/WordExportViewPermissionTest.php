<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45703')]
final class WordExportViewPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-wordexport-user';

    private const PAGE_KEY = 'pd-sec-wordexport-page';

    private const SECOND_PAGE_KEY = 'pd-sec-wordexport-page-2';

    private const PAGE_TITLE = 'pd-sec-wordexport-title';

    private const EXPORT_ID = 'pdsecwordexport';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\Document\Page $page;

    private \Pimcore\Model\Document\Page $secondPage;

    protected function setUp(): void
    {
        $this->removeFixtures();

        $this->page = $this->createPage(self::PAGE_KEY);
        $this->secondPage = $this->createPage(self::SECOND_PAGE_KEY);

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['word_export', 'documents']);
        $this->user->save();

        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
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

    public function testForbiddenElementIsSkippedAndPermittedElementIsExported(): void
    {
        $this->grantView($this->secondPage);

        $response = $this->export([
            ['type' => 'document', 'id' => $this->page->getId()],
            ['type' => 'document', 'id' => $this->secondPage->getId()],
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $html = $this->exportedHtml();
        $this->assertStringContainsString('(ID: ' . $this->secondPage->getId() . ')', $html);
        $this->assertStringNotContainsString('(ID: ' . $this->page->getId() . ')', $html);
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

    private function createPage(string $key): \Pimcore\Model\Document\Page
    {
        $page = new \Pimcore\Model\Document\Page();
        $page->setParentId(1);
        $page->setKey($key);
        $page->setTitle(self::PAGE_TITLE);
        $page->setController(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::class . '::renderAction');
        $page->setPublished(true);
        $page->save();

        return $page;
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

    private function removeFixtures(): void
    {
        @unlink($this->exportFile());

        try {
            $this->deleteUserByName(self::USERNAME);
        } finally {
            try {
                $this->deleteDocumentByKey(self::PAGE_KEY);
            } finally {
                $this->deleteDocumentByKey(self::SECOND_PAGE_KEY);
            }
        }
    }

    private function deleteDocumentByKey(string $key): void
    {
        $page = \Pimcore\Model\Document::getByPath('/' . $key);

        if ($page instanceof \Pimcore\Model\Document) {
            $page->delete();
        }
    }
}
