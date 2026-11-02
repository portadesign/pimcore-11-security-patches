<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-27461')]
final class DependencyRlikeTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;

    private const ROOT_FILENAME = 'pd-sec-dependency';

    private \Pimcore\Model\Asset\Folder $source;

    private \Pimcore\Model\Asset\Folder $target;

    /**
     * @var array<string, \Pimcore\Model\Asset\Folder>
     */
    private array $children = [];

    private \Pimcore\Model\DataObject\Folder $objectSource;

    private \Pimcore\Model\DataObject\Folder $objectTarget;

    /**
     * @var array<string, \Pimcore\Model\DataObject\Folder>
     */
    private array $objectChildren = [];

    private \Pimcore\Model\Document\Folder $documentSource;

    private \Pimcore\Model\Document\Folder $documentTarget;

    /**
     * @var array<string, \Pimcore\Model\Document\Folder>
     */
    private array $documentChildren = [];

    protected function setUp(): void
    {
        $this->removeLeftovers();

        $root = $this->createAssetFolder(parentId: 1, filename: self::ROOT_FILENAME);
        $this->source = $this->createAssetFolder(parentId: $root->getId(), filename: 'source');
        $this->target = $this->createAssetFolder(parentId: $root->getId(), filename: 'target');

        foreach (['abc', 'axc', 'a.c'] as $filename) {
            $child = $this->createAssetFolder(parentId: $root->getId(), filename: $filename);
            $this->children[$filename] = $child;

            $this->saveDependencies(sourceId: $child->getId(), targetIds: [$this->target->getId()]);
        }

        $this->saveDependencies(
            sourceId: $this->source->getId(),
            targetIds: array_map(static fn (\Pimcore\Model\Asset\Folder $child): int => $child->getId(), array_values($this->children)),
        );

        $this->createObjectAndDocumentFixtures();
    }

    private function createObjectAndDocumentFixtures(): void
    {
        $objectRoot = $this->createObjectFolder(parentId: 1, key: self::ROOT_FILENAME);
        $this->objectSource = $this->createObjectFolder(parentId: $objectRoot->getId(), key: 'source');
        $this->objectTarget = $this->createObjectFolder(parentId: $objectRoot->getId(), key: 'target');

        $documentRoot = $this->createDocumentFolder(parentId: 1, key: self::ROOT_FILENAME);
        $this->documentSource = $this->createDocumentFolder(parentId: $documentRoot->getId(), key: 'source');
        $this->documentTarget = $this->createDocumentFolder(parentId: $documentRoot->getId(), key: 'target');

        foreach (['item-one', 'item-two'] as $key) {
            $objectChild = $this->createObjectFolder(parentId: $objectRoot->getId(), key: $key);
            $this->objectChildren[$key] = $objectChild;
            $this->saveDependencies(sourceId: $objectChild->getId(), targetIds: [$this->objectTarget->getId()], type: 'object');

            $documentChild = $this->createDocumentFolder(parentId: $documentRoot->getId(), key: $key);
            $this->documentChildren[$key] = $documentChild;
            $this->saveDependencies(sourceId: $documentChild->getId(), targetIds: [$this->documentTarget->getId()], type: 'document');
        }

        $this->saveDependencies(
            sourceId: $this->objectSource->getId(),
            targetIds: array_map(static fn (\Pimcore\Model\DataObject\Folder $child): int => $child->getId(), array_values($this->objectChildren)),
            type: 'object',
        );
        $this->saveDependencies(
            sourceId: $this->documentSource->getId(),
            targetIds: array_map(static fn (\Pimcore\Model\Document\Folder $child): int => $child->getId(), array_values($this->documentChildren)),
            type: 'document',
        );
    }

    protected function tearDown(): void
    {
        $this->removeLeftovers();
    }

    /**
     * @return array<string, array{string, list<string>}>
     */
    public static function filterProvider(): array
    {
        return [
            'plain literal' => ['abc', ['abc']],
            'dot is not a wildcard' => ['a.c', ['a.c']],
            'alternation is not an operator' => ['abc|axc', []],
            'wildcard star is literal' => ['a.*', []],
            'unbalanced parenthesis is literal' => ['(abc', []],
            'closing parenthesis is literal' => ['abc)', []],
            'character class is literal' => ['[a-z]bc', []],
            'quote breakout does not over-match' => ["zzz' OR '1'='1", []],
            'quote breakout with comment does not over-match' => ["zzz' OR 1=1#", []],
            'error based extraction does not execute' => ["x' OR extractvalue(1,concat(0x7e,(SELECT version())))#", []],
            'stacked subquery does not execute' => ["x') OR (SELECT 1 FROM (SELECT SLEEP(0)) s) -- ", []],
        ];
    }

    /**
     * @param list<string> $expectedFilenames
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('filterProvider')]
    public function testRequiresFilterTreatsValueLiterally(string $value, array $expectedFilenames): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->source->getId(), 'asset');

        $rows = $dependency->getFilterRequiresByPath(0, 50, $value);

        $this->assertSame($this->expectedIds($expectedFilenames), $this->sortedIds($rows));
    }

    /**
     * @param list<string> $expectedFilenames
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('filterProvider')]
    public function testRequiredByFilterTreatsValueLiterally(string $value, array $expectedFilenames): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->target->getId(), 'asset');

        $rows = $dependency->getFilterRequiredByPath(0, 50, $value);

        $this->assertSame($this->expectedIds($expectedFilenames), $this->sortedIds($rows));
    }

    /**
     * @return array<string, array{string, list<string>}>
     */
    public static function mixedTypeFilterProvider(): array
    {
        return [
            'upper-case value matches key' => ['ITEM-ONE', ['item-one']],
            'lower-case value matches key' => ['item-one', ['item-one']],
            'upper-case value matches second key' => ['ITEM-TWO', ['item-two']],
            'upper-case value matches path segment of every child' => ['/PD-SEC-DEPENDENCY/', ['item-one', 'item-two']],
            'value matching nothing returns nothing' => ['no-such-key', []],
            'dot is not a wildcard' => ['item.one', []],
            'alternation is not an operator' => ['item-one|item-two', []],
        ];
    }

    /**
     * @param list<string> $expectedKeys
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('mixedTypeFilterProvider')]
    public function testRequiresFilterMatchesObjectsCaseInsensitively(string $value, array $expectedKeys): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->objectSource->getId(), 'object');

        $rows = $dependency->getFilterRequiresByPath(0, 50, $value);

        $this->assertSame($this->expectedTypedIds('object', $this->objectChildren, $expectedKeys), $this->typedIds($rows));
    }

    /**
     * @param list<string> $expectedKeys
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('mixedTypeFilterProvider')]
    public function testRequiredByFilterMatchesObjectsCaseInsensitively(string $value, array $expectedKeys): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->objectTarget->getId(), 'object');

        $rows = $dependency->getFilterRequiredByPath(0, 50, $value);

        $this->assertSame($this->expectedTypedIds('object', $this->objectChildren, $expectedKeys), $this->typedIds($rows));
    }

    /**
     * @param list<string> $expectedKeys
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('mixedTypeFilterProvider')]
    public function testRequiresFilterMatchesDocumentsCaseInsensitively(string $value, array $expectedKeys): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->documentSource->getId(), 'document');

        $rows = $dependency->getFilterRequiresByPath(0, 50, $value);

        $this->assertSame($this->expectedTypedIds('document', $this->documentChildren, $expectedKeys), $this->typedIds($rows));
    }

    /**
     * @param list<string> $expectedKeys
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('mixedTypeFilterProvider')]
    public function testRequiredByFilterMatchesDocumentsCaseInsensitively(string $value, array $expectedKeys): void
    {
        $dependency = \Pimcore\Model\Dependency::getBySourceId($this->documentTarget->getId(), 'document');

        $rows = $dependency->getFilterRequiredByPath(0, 50, $value);

        $this->assertSame($this->expectedTypedIds('document', $this->documentChildren, $expectedKeys), $this->typedIds($rows));
    }

    /**
     * @param array<string, \Pimcore\Model\Element\ElementInterface> $children
     * @param list<string>                                              $keys
     *
     * @return list<string>
     */
    private function expectedTypedIds(string $type, array $children, array $keys): array
    {
        $ids = array_map(static fn (string $key): string => $type . ':' . $children[$key]->getId(), $keys);
        sort($ids);

        return $ids;
    }

    /**
     * @param array<int, array{id: int|string, type: string}> $rows
     *
     * @return list<string>
     */
    private function typedIds(array $rows): array
    {
        $ids = array_map(static fn (array $row): string => $row['type'] . ':' . $row['id'], $rows);
        sort($ids);

        return $ids;
    }

    private function createObjectFolder(int $parentId, string $key): \Pimcore\Model\DataObject\Folder
    {
        $folder = new \Pimcore\Model\DataObject\Folder();
        $folder->setParentId($parentId);
        $folder->setKey($key);
        $folder->save(['versionNote' => __METHOD__ . ':' . __LINE__]);

        return $folder;
    }

    private function createDocumentFolder(int $parentId, string $key): \Pimcore\Model\Document\Folder
    {
        $folder = new \Pimcore\Model\Document\Folder();
        $folder->setParentId($parentId);
        $folder->setKey($key);
        $folder->save();

        return $folder;
    }

    /**
     * @param list<string> $filenames
     *
     * @return list<int>
     */
    private function expectedIds(array $filenames): array
    {
        $ids = array_map(fn (string $filename): int => $this->children[$filename]->getId(), $filenames);
        sort($ids);

        return $ids;
    }

    /**
     * @param array<int, array{id: int|string, type: string}> $rows
     *
     * @return list<int>
     */
    private function sortedIds(array $rows): array
    {
        $ids = array_map(static fn (array $row): int => (int) $row['id'], $rows);
        sort($ids);

        return $ids;
    }

    /**
     * @param list<int> $targetIds
     */
    private function saveDependencies(int $sourceId, array $targetIds, string $type = 'asset'): void
    {
        $dependency = new \Pimcore\Model\Dependency();
        $dependency->setSourceId($sourceId);
        $dependency->setSourceType($type);

        foreach ($targetIds as $targetId) {
            $dependency->addRequirement($targetId, $type);
        }

        $dependency->getDao()->save();
    }

    private function removeLeftovers(): void
    {
        try {
            $this->deleteAssetByPath('/' . self::ROOT_FILENAME);
        } finally {
            try {
                \Pimcore\Model\DataObject::getByPath('/' . self::ROOT_FILENAME)?->delete();
            } finally {
                \Pimcore\Model\Document::getByPath('/' . self::ROOT_FILENAME)?->delete();
            }
        }
    }
}
