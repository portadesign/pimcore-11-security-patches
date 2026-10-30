<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-44741')]
final class TranslationGridFilterTest extends \PHPUnit\Framework\TestCase
{
    private const DOMAIN = \Pimcore\Model\Translation::DOMAIN_DEFAULT;

    private const KEY_PREFIX = 'pd-sec-grid-';

    /**
     * @var array<string, int>
     */
    private const FIXTURES = [
        'pd-sec-grid-1' => 1767268800,
        'pd-sec-grid-2' => 1767355200,
        'pd-sec-grid-3' => 1772366400,
    ];

    private string $tableName;

    protected function setUp(): void
    {
        \Pimcore\Db::get()->executeStatement('SET time_zone = ' . \Pimcore\Db::get()->quote(date('P', self::FIXTURES['pd-sec-grid-1'])));
        $this->removeFixtures();

        $probe = new \Pimcore\Model\Translation();
        $probe->setDomain(self::DOMAIN);
        $this->tableName = $probe->getDao()->getDatabaseTableName();

        foreach (self::FIXTURES as $key => $createdAt) {
            $translation = \Pimcore\Model\Translation::getByKey($key, self::DOMAIN, true);
            $translation->addTranslation('en', 'text of ' . $key);
            $translation->setCreationDate($createdAt);
            $translation->save();
        }
    }

    protected function tearDown(): void
    {
        $this->removeFixtures();
        \Pimcore\Db::get()->executeStatement('SET time_zone = DEFAULT');
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function injectedFilterProvider(): array
    {
        return [
            'union select through date equality filter from advisory' => [[
                'property' => '1))) UNION SELECT password FROM users WHERE ((1',
                'type' => 'date',
                'operator' => 'eq',
                'value' => '2026-01-01',
            ]],
            'union select through date less-than filter' => [[
                'property' => '1 UNION SELECT password FROM users #',
                'type' => 'date',
                'operator' => 'lt',
                'value' => '2026-01-01',
            ]],
            'subquery through string filter property' => [[
                'property' => 'key) OR (SELECT SLEEP(0)) OR (1',
                'type' => 'string',
                'operator' => 'like',
                'value' => 'x',
            ]],
            'comment bypass of the double dash strip' => [[
                'property' => 'key/**/OR/**/1=1',
                'type' => 'string',
                'operator' => 'like',
                'value' => 'x',
            ]],
            'column of another table' => [[
                'property' => 'users.password',
                'type' => 'string',
                'operator' => 'like',
                'value' => 'a',
            ]],
            'date injection on a modification date lookalike' => [[
                'property' => 'modificationDate) OR (1=1',
                'type' => 'date',
                'operator' => 'gt',
                'value' => '2026-01-01',
            ]],
        ];
    }

    /**
     * @return array<string, array{array<string, string>, list<string>}>
     */
    public static function legitimateFilterProvider(): array
    {
        return [
            'creation date after' => [
                ['property' => 'creationDate', 'type' => 'date', 'operator' => 'gt', 'value' => '2026-02-01'],
                ['pd-sec-grid-3'],
            ],
            'creation date before' => [
                ['property' => 'creationDate', 'type' => 'date', 'operator' => 'lt', 'value' => '2026-02-01'],
                ['pd-sec-grid-1', 'pd-sec-grid-2'],
            ],
            'creation date on a day' => [
                ['property' => 'creationDate', 'type' => 'date', 'operator' => 'eq', 'value' => '2026-01-01'],
                ['pd-sec-grid-1'],
            ],
            'key substring' => [
                ['property' => 'key', 'type' => 'string', 'operator' => 'like', 'value' => 'grid-2'],
                ['pd-sec-grid-2'],
            ],
            'text substring' => [
                ['property' => 'text', 'type' => 'string', 'operator' => 'like', 'value' => 'text of pd-sec-grid-3'],
                ['pd-sec-grid-3'],
            ],
        ];
    }

    /**
     * @param array<string, string> $filter
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('injectedFilterProvider')]
    public function testInjectedFilterPropertyProducesNoCondition(array $filter): void
    {
        $this->assertSame([], $this->filterCondition($filter));
    }

    /**
     * @param array<string, string> $filter
     * @param list<string> $expectedKeys
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('legitimateFilterProvider')]
    public function testLegitimateFilterSelectsMatchingTranslations(array $filter, array $expectedKeys): void
    {
        $condition = $this->filterCondition($filter);
        $this->assertNotSame([], $condition);

        $list = new \Pimcore\Model\Translation\Listing();
        $list->setDomain(self::DOMAIN);
        $list->setLanguages(['en']);
        $list->setOrderKey($this->tableName . '.key', false);
        $list->setCondition(
            '(' . $condition['condition'] . ') AND ' . $this->tableName . '.key LIKE ' . \Pimcore\Db::get()->quote(self::KEY_PREFIX . '%'),
            $condition['params'],
        );

        $keys = array_map(static fn (\Pimcore\Model\Translation $translation): string => $translation->getKey(), $list->load());

        $this->assertSame($expectedKeys, $keys);
    }

    /**
     * @param array<string, string> $filter
     *
     * @return array<string, mixed>
     */
    private function filterCondition(array $filter): array
    {
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\TranslationController::class);
        $request = new \Symfony\Component\HttpFoundation\Request(['filter' => json_encode([$filter], JSON_THROW_ON_ERROR)]);

        $method = new \ReflectionMethod($controller, 'getGridFilterCondition');

        return $method->invoke($controller, $request, $this->tableName, false, true);
    }

    private function removeFixtures(): void
    {
        foreach (array_keys(self::FIXTURES) as $key) {
            $translation = \Pimcore\Model\Translation::getByKey($key, self::DOMAIN);

            if ($translation instanceof \Pimcore\Model\Translation) {
                $translation->delete();
            }
        }
    }
}
