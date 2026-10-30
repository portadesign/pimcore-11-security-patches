<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-5394')]
final class CompositeIndexTest extends \PHPUnit\Framework\TestCase
{
    private const TABLE = 'pd_sec_composite_scratch';

    private \Doctrine\DBAL\Connection $db;

    protected function setUp(): void
    {
        $this->db = \Pimcore\Db::get();
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY, a VARCHAR(20), b VARCHAR(20), c VARCHAR(20))');
    }

    protected function tearDown(): void
    {
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIdentifierProvider(): array
    {
        return [
            'backtick' => ['a`b'],
            'semicolon' => ['a;b'],
            'space' => ['a b'],
            'leading digit' => ['1abc'],
            'empty' => [''],
            'too long' => [str_repeat('a', 65)],
            'column breakout from advisory' => ['a), DROP COLUMN `c` -- '],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdentifierProvider')]
    public function testIndexColumnWithInvalidIdentifierIsRejected(string $column): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index('poc_idx', [$column])]);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdentifierProvider')]
    public function testIndexKeyWithInvalidIdentifierIsRejected(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index($key, ['a'])]);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdentifierProvider')]
    public function testClassDefinitionRejectsInvalidIndexKeyOnAssignment(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition())->setCompositeIndices([$this->index($key, ['a'])]);
    }

    public function testColumnInjectionDoesNotAlterTableSchema(): void
    {
        try {
            $this->classDao()->updateCompositeIndices(
                self::TABLE,
                'query',
                [$this->index('poc_idx', ['a), DROP COLUMN `c` -- '])],
            );
        } catch (\Throwable) {
        }

        $this->assertSame(['oo_id', 'a', 'b', 'c'], $this->columnNames());
    }

    public function testKeyInjectionDoesNotAlterTableSchema(): void
    {
        try {
            $this->classDao()->updateCompositeIndices(
                self::TABLE,
                'query',
                [$this->index('k` (a), DROP COLUMN `c`, ADD INDEX `z', ['a'])],
            );
        } catch (\Throwable) {
        }

        $this->assertSame(['oo_id', 'a', 'b', 'c'], $this->columnNames());
    }

    public function testValidIndexIsCreatedWithColumnsInOrderAndDroppedAgain(): void
    {
        $dao = $this->classDao();

        $dao->updateCompositeIndices(self::TABLE, 'query', [$this->index('my-index_1', ['b', 'a'])]);

        $this->assertSame(['b', 'a'], $this->indexColumns('c_my-index_1'));

        $dao->updateCompositeIndices(self::TABLE, 'query', []);

        $this->assertSame([], $this->indexColumns('c_my-index_1'));
    }

    /**
     * @param list<string> $columns
     *
     * @return array{index_key: string, index_type: string, index_columns: list<string>}
     */
    private function index(string $key, array $columns): array
    {
        return ['index_key' => $key, 'index_type' => 'query', 'index_columns' => $columns];
    }

    private function classDao(): \Pimcore\Model\DataObject\ClassDefinition\Dao
    {
        $dao = (new \Pimcore\Model\DataObject\ClassDefinition())->getDao();
        \assert($dao instanceof \Pimcore\Model\DataObject\ClassDefinition\Dao);

        return $dao;
    }

    /**
     * @return list<string>
     */
    private function columnNames(): array
    {
        return array_map(
            static fn (array $row): string => (string) $row['Field'],
            $this->db->fetchAllAssociative('SHOW COLUMNS FROM `' . self::TABLE . '`'),
        );
    }

    /**
     * @return list<string>
     */
    private function indexColumns(string $indexName): array
    {
        $rows = $this->db->fetchAllAssociative(
            'SHOW INDEXES FROM `' . self::TABLE . '` WHERE Key_name = ?',
            [$indexName],
        );
        usort($rows, static fn (array $left, array $right): int => (int) $left['Seq_in_index'] <=> (int) $right['Seq_in_index']);

        return array_map(static fn (array $row): string => (string) $row['Column_name'], $rows);
    }
}
