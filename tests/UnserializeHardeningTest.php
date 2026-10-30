<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55220')]
#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45162')]
final class UnserializeHardeningTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;

    private const FIXTURE_FOLDER = 'pd-sec-unserialize';

    private const CUSTOM_LAYOUT_SCOPE = 'pimcore_object_custom_layout';

    /**
     * @var list<\Closure>
     */
    private array $cleanups = [];

    protected function setUp(): void
    {
        $this->resetCanary();
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->cleanups) as $cleanup) {
            $cleanup();
        }

        $this->cleanups = [];
        $this->deleteAssetByPath('/' . self::FIXTURE_FOLDER);
        $this->resetCanary();
    }

    /**
     * @return array<string, array{array<int, string>|bool}>
     */
    public static function denyAllProvider(): array
    {
        return [
            'empty allowlist' => [[]],
            'boolean false' => [false],
        ];
    }

    /**
     * @param array<int, string>|bool $allowedClasses
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('denyAllProvider')]
    public function testSerializeDoesNotInstantiateClassOutsideAllowlist(array|bool $allowedClasses): void
    {
        $result = \Pimcore\Tool\Serialize::unserialize($this->serialized(fn (): mixed => $this->canary()), $allowedClasses);

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran during unserialize().');
    }

    public function testSerializeKeepsOnlyAllowlistedClasses(): void
    {
        $payload = $this->serialized(fn (): mixed => ['allowed' => $this->canary(), 'foreign' => new \stdClass()]);

        $result = \Pimcore\Tool\Serialize::unserialize($payload, [\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class]);

        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class, $result['allowed']);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result['foreign']);
    }

    public function testSerializeReturnsEmptyInputUnchanged(): void
    {
        $this->assertNull(\Pimcore\Tool\Serialize::unserialize(null, []));
        $this->assertSame('', \Pimcore\Tool\Serialize::unserialize('', []));
    }

    public function testHotspotimageDoesNotInstantiateForeignClassInMetadata(): void
    {
        $field = $this->hotspotField();
        $payload = $this->serialized(fn (): mixed => ['hotspots' => [['name' => 'spot', 'data' => [$this->canary()]]]]);

        $value = $field->getDataFromResource(['hs__image' => $this->fixtureImageId(), 'hs__hotspots' => $payload]);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Hotspotimage::class, $value);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $value->getHotspots()[0]['data'][0]);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Hotspotimage metadata.');
    }

    public function testHotspotimageKeepsLegitimateMarkerItems(): void
    {
        $field = $this->hotspotField();
        $item = new \Pimcore\Model\Element\Data\MarkerHotspotItem(['name' => 'label', 'type' => 'textfield', 'value' => 'v']);
        $payload = $this->serialized(fn (): mixed => ['hotspots' => [['name' => 'spot', 'data' => [$item]]]]);

        $value = $field->getDataFromResource(['hs__image' => $this->fixtureImageId(), 'hs__hotspots' => $payload]);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Hotspotimage::class, $value);
        $restored = $value->getHotspots()[0]['data'][0];
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $restored);
        $this->assertSame('v', $restored->getValue());
    }

    public function testSiteDomainsDoNotInstantiateForeignClass(): void
    {
        $site = new \Pimcore\Model\Site();

        try {
            $site->setDomains($this->serialized(fn (): mixed => ['a.example.com', $this->canary()]));
        } catch (\TypeError) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site::setDomains().');
    }

    public function testSiteDomainsKeepSerializedDomainList(): void
    {
        $site = new \Pimcore\Model\Site();

        $site->setDomains(serialize(['a.example.com', '*.example.org']));

        $this->assertSame(['a.example.com', '*.example.org'], $site->getDomains());
    }

    public function testSiteLocalizedErrorDocumentsDoNotInstantiateForeignClass(): void
    {
        $site = new \Pimcore\Model\Site();

        $site->setLocalizedErrorDocuments($this->serialized(fn (): mixed => ['en' => '/error', 'cs' => $this->canary()]));

        $this->assertSame('/error', $site->getLocalizedErrorDocuments()['en']);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $site->getLocalizedErrorDocuments()['cs']);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site::setLocalizedErrorDocuments().');
    }

    public function testSiteWildcardLookupDoesNotInstantiateForeignClassFromDatabase(): void
    {
        $this->insertSiteRow($this->serialized(fn (): mixed => ['*.pd-sec.example', $this->canary()]));

        try {
            (new \Pimcore\Model\Site())->getDao()->getByDomain('shop.pd-sec.example');
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site\\Dao::getByDomain().');
    }

    public function testSiteWildcardLookupStillResolvesLegitimateWildcardDomain(): void
    {
        $siteId = $this->insertSiteRow(serialize(['*.pd-sec.example']));

        $site = new \Pimcore\Model\Site();
        $site->getDao()->getByDomain('shop.pd-sec.example');

        $this->assertSame($siteId, $site->getId());
    }

    public function testCustomLayoutLegacyPayloadDoesNotInstantiateForeignClass(): void
    {
        $id = $this->storeCustomLayout($this->serialized(fn (): mixed => $this->canary()));

        try {
            (new \Pimcore\Model\DataObject\ClassDefinition\CustomLayout())->getDao()->getById($id);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in CustomLayout\\Dao::getById().');
    }

    public function testCustomLayoutLegacyPayloadStillLoadsSerializedLayoutArray(): void
    {
        $layout = [
            'datatype' => 'layout',
            'fieldtype' => 'panel',
            'name' => 'Layout',
            'children' => [['datatype' => 'data', 'fieldtype' => 'input', 'name' => 'title', 'title' => 'Title']],
        ];
        $id = $this->storeCustomLayout(serialize($layout));

        $customLayout = new \Pimcore\Model\DataObject\ClassDefinition\CustomLayout();
        $customLayout->getDao()->getById($id);

        $definitions = $customLayout->getLayoutDefinitions();
        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Layout\Panel::class, $definitions);
        $this->assertSame('title', $definitions->getChildren()[0]->getName());
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function foreignTmpStorePayloadProvider(): array
    {
        return [
            'top level object' => [false],
            'nested in array' => [true],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignTmpStorePayloadProvider')]
    public function testTmpStoreRejectsForeignClass(bool $nested): void
    {
        $data = $nested ? ['wrapper' => ['inner' => $this->canary()]] : $this->canary();
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, $data);
        $this->resetCanary();

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertNull($item);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in TmpStore\\Dao::getById().');
    }

    public function testTmpStoreReturnsPlainArray(): void
    {
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, ['a' => 1, 'b' => ['c' => 'd']]);

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertSame(['a' => 1, 'b' => ['c' => 'd']], $item->getData());
    }

    public function testTmpStoreReturnsAllowlistedThumbnailConfig(): void
    {
        $id = $this->tmpStoreId();
        $config = new \Pimcore\Model\Asset\Image\Thumbnail\Config();
        $config->setName('pd-sec-thumbnail');
        \Pimcore\Model\Tool\TmpStore::set($id, $config);

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $item->getData());
        $this->assertSame('pd-sec-thumbnail', $item->getData()->getName());
    }

    private function hotspotField(): \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage();
        $field->setName('hs');

        return $field;
    }

    private function fixtureImageId(): int
    {
        return $this->createAssetFolder(parentId: 1, filename: self::FIXTURE_FOLDER)->getId();
    }

    private function tmpStoreId(): string
    {
        $id = 'pd-sec-' . bin2hex(random_bytes(6));
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Tool\TmpStore::delete($id);
        };

        return $id;
    }

    private function insertSiteRow(string $serializedDomains): int
    {
        $db = \Pimcore\Db::get();
        $db->insert('sites', ['domains' => $serializedDomains]);
        $siteId = (int) $db->lastInsertId();
        $this->cleanups[] = static function () use ($siteId): void {
            \Pimcore\Db::get()->delete('sites', ['id' => $siteId]);
        };

        return $siteId;
    }

    private function storeCustomLayout(string $serializedLayoutDefinitions): string
    {
        $id = 'pd_sec_' . bin2hex(random_bytes(4));
        \Pimcore\Model\Tool\SettingsStore::set(
            $id,
            json_encode(['id' => $id, 'name' => $id, 'layoutDefinitions' => $serializedLayoutDefinitions], JSON_THROW_ON_ERROR),
            'string',
            self::CUSTOM_LAYOUT_SCOPE,
        );
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Tool\SettingsStore::delete($id, self::CUSTOM_LAYOUT_SCOPE);
        };

        return $id;
    }

    private function canary(): object
    {
        return new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary();
    }

    private function serialized(\Closure $factory): string
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized($factory);
    }

    private function resetCanary(): void
    {
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();
    }

    private function canaryExecutions(): int
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions;
    }
}
