<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45704')]
final class CustomReportsShareTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\ReportScratchTable;

    private const REPORT_PREFIX = 'pd-sec-share-report-';

    private const SCOPE = 'pimcore_custom_reports';

    private const USERNAME = 'pd-sec-share-user';

    private const OTHER_USERNAME = 'pd-sec-share-other';

    private const ROLE = 'pd-sec-share-role';

    private const OTHER_ROLE = 'pd-sec-share-other-role';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User\Role $role;

    private \Pimcore\Model\User\Role $otherRole;

    private string $reportName;

    /**
     * @var list<string>
     */
    private array $exportFiles = [];

    protected function setUp(): void
    {
        $this->removeFixtures();
        $this->createReportScratchTable();
        $this->reportName = self::REPORT_PREFIX . bin2hex(random_bytes(4));

        $this->role = \Pimcore\Model\User\Role::create(['parentId' => 0, 'name' => self::ROLE]);
        $this->otherRole = \Pimcore\Model\User\Role::create(['parentId' => 0, 'name' => self::OTHER_ROLE]);

        $this->user = $this->createUser(self::USERNAME, ['reports'], [$this->role->getId()]);
        $this->createUser(self::OTHER_USERNAME, ['reports'], []);

        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);

        try {
            $this->removeFixtures();
        } finally {
            $this->dropReportScratchTable();
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function actionProvider(): array
    {
        return [
            'get' => ['get'],
            'data' => ['data'],
            'chart' => ['chart'],
            'drill-down options' => ['drillDownOptions'],
            'create csv' => ['createCsv'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testUnsharedReportIsForbidden(string $action): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME], roleNames: [self::OTHER_ROLE]);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->call($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportWithoutAnySharingIsForbidden(string $action): void
    {
        $this->createReport(shareGlobally: false);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->call($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportSharedWithUserIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportSharedWithRoleOfUserIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: false, roleNames: [self::OTHER_ROLE, self::ROLE]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportSharedGloballyIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: true);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testAdminAccessesUnsharedReport(string $action): void
    {
        $admin = $this->createUser('pd-sec-share-admin', [], [], true);
        $this->authenticate($admin);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportEditorAccessesUnsharedReport(string $action): void
    {
        $this->user->setPermissions(['reports', 'reports_config']);
        $this->user->save();
        $this->authenticate($this->user);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    public function testReportEditorWithoutReportsPermissionStillReadsUnsharedReport(): void
    {
        $this->user->setPermissions(['reports_config']);
        $this->user->save();
        $this->authenticate($this->user);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call('get')->getStatusCode());
    }

    public function testListingOmitsUnsharedReport(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertNotContains($this->reportName, $this->listedReportNames());
    }

    public function testListingContainsSharedReport(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $this->assertContains($this->reportName, $this->listedReportNames());
    }

    public function testListingContainsReportSharedWithRole(): void
    {
        $this->createReport(shareGlobally: false, roleNames: [self::ROLE]);

        $this->assertContains($this->reportName, $this->listedReportNames());
    }

    public function testUnknownReportIsNotFound(): void
    {
        $this->expectException(\Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class);

        $this->call('get');
    }

    public function testSharedCsvExportContainsRows(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $response = $this->call('createCsv');

        $this->assertSame(200, $response->getStatusCode());
        $csv = (string) file_get_contents(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . basename(end($this->exportFiles)));

        $this->assertStringContainsString('plain', $csv);
    }

    public function testForbiddenCsvExportWritesNoFile(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);
        $before = glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-*.csv') ?: [];

        try {
            $this->call('createCsv');
            $this->fail('Unshared report was exported.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $this->assertSame($before, glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-*.csv') ?: []);
    }

    private function call(string $action): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = $this->controller();

        $response = match ($action) {
            'get' => $controller->getAction(new \Symfony\Component\HttpFoundation\Request(['name' => $this->reportName])),
            'data' => $controller->dataAction($this->post(['name' => $this->reportName, 'start' => 0, 'limit' => 10])),
            'chart' => $controller->chartAction($this->post(['name' => $this->reportName])),
            'drillDownOptions' => $controller->drillDownOptionsAction($this->post(['name' => $this->reportName, 'field' => 'note'])),
            'createCsv' => $controller->createCsvAction(new \Symfony\Component\HttpFoundation\Request(['name' => $this->reportName, 'headers' => 1, 'drillDownFilters' => '[]'])),
        };

        if ('createCsv' === $action) {
            $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
            $this->exportFiles[] = $payload['exportFile'];
        }

        return $response;
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function post(array $parameters): \Symfony\Component\HttpFoundation\Request
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: $parameters);
        $request->setMethod('POST');

        return $request;
    }

    private function controller(): \Pimcore\Bundle\CustomReportsBundle\Controller\Reports\CustomReportController
    {
        $container = \Pimcore::getContainer();

        $controller = new \Pimcore\Bundle\CustomReportsBundle\Controller\Reports\CustomReportController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    /**
     * @return list<string>
     */
    private function listedReportNames(): array
    {
        $response = $this->controller()->getReportConfigAction(new \Symfony\Component\HttpFoundation\Request());
        $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        return array_column($payload['reports'], 'name');
    }

    /**
     * @param list<string> $userNames
     * @param list<string> $roleNames
     */
    private function createReport(bool $shareGlobally, array $userNames = [], array $roleNames = []): void
    {
        $now = time();

        \Pimcore\Model\Tool\SettingsStore::set(
            $this->reportName,
            json_encode([
                'name' => $this->reportName,
                'niceName' => 'pd-sec share report',
                'dataSourceConfig' => [(array) $this->reportConfig(['sql' => 'id, note'])],
                'columnConfiguration' => [
                    ['name' => 'id', 'display' => true, 'export' => true, 'order' => true, 'label' => 'id'],
                    ['name' => 'note', 'display' => true, 'export' => true, 'order' => true, 'label' => 'note'],
                ],
                'shareGlobally' => $shareGlobally,
                'sharedUserNames' => $userNames,
                'sharedRoleNames' => $roleNames,
                'menuShortcut' => false,
                'creationDate' => $now,
                'modificationDate' => $now,
            ], JSON_THROW_ON_ERROR),
            \Pimcore\Model\Tool\SettingsStore::TYPE_STRING,
            self::SCOPE,
        );
    }

    /**
     * @param list<string> $permissions
     * @param list<int> $roleIds
     */
    private function createUser(string $name, array $permissions, array $roleIds, bool $admin = false): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => $admin,
        ]);
        $user->setPermissions($permissions);
        $user->setRoles($roleIds);
        $user->save();

        return $user;
    }

    private function removeFixtures(): void
    {
        foreach ($this->exportFiles as $file) {
            @unlink(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . basename($file));
        }
        $this->exportFiles = [];

        foreach (\Pimcore\Model\Tool\SettingsStore::getIdsByScope(self::SCOPE) as $id) {
            if (str_starts_with($id, self::REPORT_PREFIX)) {
                \Pimcore\Model\Tool\SettingsStore::delete($id, self::SCOPE);
            }
        }

        foreach ([self::USERNAME, self::OTHER_USERNAME, 'pd-sec-share-admin'] as $name) {
            $this->deleteUserByName($name);
        }

        foreach ([self::ROLE, self::OTHER_ROLE] as $name) {
            $role = \Pimcore\Model\User\Role::getByName($name);
            $role?->delete();
        }
    }
}
