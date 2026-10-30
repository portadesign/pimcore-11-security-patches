<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
final class CustomReportsSqlFragmentTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\ReportScratchTable;

    protected function setUp(): void
    {
        $this->createReportScratchTable();
    }

    protected function tearDown(): void
    {
        $this->dropReportScratchTable();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function unsafeFragmentProvider(): array
    {
        return [
            'semicolon in sql' => ['sql', 'id; SELECT 1'],
            'comment dash in sql' => ['sql', 'id -- trailing'],
            'hash comment in sql' => ['sql', 'id # trailing'],
            'block comment opener in sql' => ['sql', 'id /* x'],
            'block comment closer in sql' => ['sql', 'id */ x'],
            'semicolon in from' => ['from', 'pd_sec_report_scratch; SELECT 1'],
            'comment dash in from' => ['from', 'pd_sec_report_scratch -- x'],
            'hash comment in where' => ['where', '1 = 1 #'],
            'stacked update in where' => ['where', "id = 1; UPDATE pd_sec_report_scratch SET secret = 'pwned'"],
            'block comment in where' => ['where', 'id = 1 /**/ OR /**/ 1 = 1'],
            'semicolon in groupby' => ['groupby', 'id; SELECT 1'],
            'comment dash in groupby' => ['groupby', 'id -- x'],
            'leading drop in sql' => ['sql', 'DROP TABLE pd_sec_report_scratch'],
            'leading delete in sql' => ['sql', 'DELETE FROM pd_sec_report_scratch'],
            'leading update in sql' => ['sql', "UPDATE pd_sec_report_scratch SET secret = 'pwned'"],
            'leading insert in sql' => ['sql', 'INSERT INTO pd_sec_report_scratch VALUES (9, 1, 1, 1)'],
            'leading alter in sql' => ['sql', 'ALTER TABLE pd_sec_report_scratch ADD x INT'],
            'leading create in sql' => ['sql', 'CREATE TABLE pd_sec_report_created (a INT)'],
            'leading truncate in sql' => ['sql', 'TRUNCATE pd_sec_report_scratch'],
            'leading drop in where' => ['where', 'DROP TABLE pd_sec_report_scratch'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unsafeFragmentProvider')]
    public function testGetDataRejectsUnsafeFragment(string $key, string $fragment): void
    {
        $adapter = $this->reportAdapter($this->reportConfig([$key => $fragment]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: /');

        $adapter->getData([], null, null, 0, 10);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unsafeFragmentProvider')]
    public function testGetColumnsRejectsUnsafeFragment(string $key, string $fragment): void
    {
        $config = $this->reportConfig([$key => $fragment]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: /');

        $this->reportAdapter($config)->getColumns($config);
    }

    public function testNonStringFragmentIsRejected(): void
    {
        $adapter = $this->reportAdapter($this->reportConfig(['where' => ['1 = 1']]));

        $this->expectExceptionObject(new \InvalidArgumentException('Invalid "where" SQL fragment; expected string.'));

        $adapter->getData([], null, null, 0, 10);
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-44739')]
    public function testAdvisoryStackedUpdatePayloadLeavesDataUntouched(): void
    {
        $payload = "id=1)/**/OR/**/1=1;/**/UPDATE/**/pd_sec_report_scratch/**/SET/**/secret='pwned'/**/WHERE/**/id=1;-- -";
        $config = $this->reportConfig(['sql' => '*', 'where' => $payload]);

        try {
            $this->reportAdapter($config)->getColumns($config);
        } catch (\Throwable) {
        }

        $this->assertSame(['original', 'original', 'original', 'original', 'original'], $this->storedSecrets());
    }

    public function testQuotedTokensAreNotTreatedAsUnsafe(): void
    {
        $where = "note = 'semi;colon' OR note = \"dash -- x\" OR note = 'hash # y' OR note = 'c /* x */'";
        $adapter = $this->reportAdapter($this->reportConfig(['where' => $where]));

        $result = $adapter->getData([], 'id', 'ASC', 0, 10);

        $this->assertSame([1, 2, 3, 4], array_map('intval', array_column($result['data'], 'id')));
        $this->assertSame(4, (int) $result['total']);
    }

    public function testKeywordSubstringsInIdentifiersAndFunctionsAreNotTreatedAsUnsafe(): void
    {
        $config = $this->reportConfig(['sql' => "id, updated_at, INSERT(note, 1, 2, 'xx') AS patched", 'where' => 'id = 5']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame([['id' => 5, 'updated_at' => 50, 'patched' => 'xxain']], $this->normalizeRows($result['data']));
        $this->assertSame(1, (int) $result['total']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function configuredReportProvider(): array
    {
        $names = [];

        foreach (\Pimcore\Bundle\CustomReportsBundle\Tool\Config::getReportsList() as $report) {
            $names[(string) $report['id']] = [(string) $report['id']];
        }

        return $names;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('configuredReportProvider')]
    public function testConfiguredHostReportStillRuns(string $reportName): void
    {
        $report = \Pimcore\Bundle\CustomReportsBundle\Tool\Config::getByName($reportName);
        $this->assertInstanceOf(\Pimcore\Bundle\CustomReportsBundle\Tool\Config::class, $report);

        $dataSources = $report->getDataSourceConfig();
        $dataSources = is_array($dataSources) ? $dataSources : [$dataSources];
        $dataSource = $dataSources[0] ?? null;

        if (!$dataSource instanceof \stdClass || ($dataSource->type ?? 'sql') !== 'sql') {
            $this->markTestSkipped(sprintf('Report "%s" does not use the SQL adapter.', $reportName));
        }

        $result = \Pimcore\Bundle\CustomReportsBundle\Tool\Config::getAdapter($dataSource, $report)->getData([], null, null, 0, 5);

        $this->assertLessThanOrEqual(5, count($result['data']));
        $this->assertGreaterThanOrEqual(count($result['data']), (int) $result['total']);
    }

    /**
     * @param list<array<string, mixed>> $rows
     *
     * @return list<array<string, int|string>>
     */
    private function normalizeRows(array $rows): array
    {
        return array_map(
            static fn (array $row): array => array_map(
                static fn (mixed $value): int|string => is_numeric($value) ? (int) $value : (string) $value,
                $row,
            ),
            $rows,
        );
    }
}
