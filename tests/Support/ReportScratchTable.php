<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait ReportScratchTable
{
    private const REPORT_TABLE = 'pd_sec_report_scratch';

    protected function createReportScratchTable(): void
    {
        $db = \Pimcore\Db::get();
        $db->executeStatement('DROP TABLE IF EXISTS `' . self::REPORT_TABLE . '`');
        $db->executeStatement(
            'CREATE TABLE `' . self::REPORT_TABLE . '` (id INT NOT NULL PRIMARY KEY, note VARCHAR(100), secret VARCHAR(100), updated_at INT)'
        );

        $rows = [
            [1, 'semi;colon', 'original', 10],
            [2, 'dash -- x', 'original', 20],
            [3, 'hash # y', 'original', 30],
            [4, 'c /* x */', 'original', 40],
            [5, 'plain', 'original', 50],
        ];

        foreach ($rows as [$id, $note, $secret, $updatedAt]) {
            $db->insert(self::REPORT_TABLE, ['id' => $id, 'note' => $note, 'secret' => $secret, 'updated_at' => $updatedAt]);
        }
    }

    protected function dropReportScratchTable(): void
    {
        \Pimcore\Db::get()->executeStatement('DROP TABLE IF EXISTS `' . self::REPORT_TABLE . '`');
    }

    /**
     * @param array<string, mixed> $overrides
     */
    protected function reportConfig(array $overrides = []): \stdClass
    {
        return (object) array_merge(
            ['type' => 'sql', 'sql' => 'id, note', 'from' => self::REPORT_TABLE, 'where' => '', 'groupby' => ''],
            $overrides,
        );
    }

    protected function reportAdapter(\stdClass $config): \Pimcore\Bundle\CustomReportsBundle\Tool\Adapter\Sql
    {
        return new \Pimcore\Bundle\CustomReportsBundle\Tool\Adapter\Sql($config);
    }

    /**
     * @return list<string>
     */
    protected function storedSecrets(): array
    {
        return array_map(
            'strval',
            \Pimcore\Db::get()->fetchFirstColumn('SELECT secret FROM `' . self::REPORT_TABLE . '` ORDER BY id'),
        );
    }
}
