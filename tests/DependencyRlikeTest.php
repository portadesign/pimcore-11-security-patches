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
    private function saveDependencies(int $sourceId, array $targetIds): void
    {
        $dependency = new \Pimcore\Model\Dependency();
        $dependency->setSourceId($sourceId);
        $dependency->setSourceType('asset');

        foreach ($targetIds as $targetId) {
            $dependency->addRequirement($targetId, 'asset');
        }

        $dependency->getDao()->save();
    }

    private function removeLeftovers(): void
    {
        $this->deleteAssetByPath('/' . self::ROOT_FILENAME);
    }
}
