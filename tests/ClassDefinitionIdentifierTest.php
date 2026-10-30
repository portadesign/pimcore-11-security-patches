<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55072')]
final class ClassDefinitionIdentifierTest extends \PHPUnit\Framework\TestCase
{
    private \Closure $persistenceSentinel;

    protected function setUp(): void
    {
        $this->persistenceSentinel = static function (): never {
            throw new \RuntimeException('persistence reached');
        };

        $dispatcher = \Pimcore::getEventDispatcher();
        $dispatcher->addListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_ADD, $this->persistenceSentinel);
        $dispatcher->addListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_UPDATE, $this->persistenceSentinel);
    }

    protected function tearDown(): void
    {
        $dispatcher = \Pimcore::getEventDispatcher();
        $dispatcher->removeListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_ADD, $this->persistenceSentinel);
        $dispatcher->removeListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_UPDATE, $this->persistenceSentinel);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIdProvider(): array
    {
        return [
            'embedded newline' => ["valid\nmalicious"],
            'trailing newline' => ["valid\n"],
            'sql payload from advisory' => ['1 UNION SELECT password FROM users-- '],
            'space' => ['a b'],
            'semicolon' => ['a;b'],
            'dash' => ['a-b'],
            'backtick' => ['a`b'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'embedded newline' => ["Valid\nName"],
            'trailing newline' => ["ValidName\n"],
            'space' => ['Bad Name'],
            'semicolon' => ['Bad;Name'],
            'leading digit' => ['1Name'],
            'dash' => ['Bad-Name'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function existingClassProvider(): array
    {
        $cases = [];

        foreach (glob(PIMCORE_CLASS_DEFINITION_DIRECTORY . '/definition_*.php') ?: [] as $file) {
            $name = substr(basename($file, '.php'), strlen('definition_'));
            $cases[$name] = [$name];
        }

        return $cases;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdProvider')]
    public function testSaveRejectsInvalidId(string $id): void
    {
        $class = $this->newClass(id: $id, name: 'ValidName');

        $this->expectExceptionObject(new \Exception(sprintf('Invalid ID `%s` for class definition ValidName', $id)));

        $class->save(saveDefinitionFile: false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testSaveRejectsInvalidName(string $name): void
    {
        $class = $this->newClass(id: 'ValidId1', name: $name);

        $this->expectExceptionObject(new \Exception(sprintf('Invalid name for class definition: %s', $name)));

        $class->save(saveDefinitionFile: false);
    }

    public function testSaveAcceptsValidIdAndName(): void
    {
        $class = $this->newClass(id: 'ValidId_1', name: 'ValidName_1');

        $this->expectExceptionObject(new \RuntimeException('persistence reached'));

        $class->save(saveDefinitionFile: false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('existingClassProvider')]
    public function testExistingHostClassPassesValidation(string $name): void
    {
        $class = \Pimcore\Model\DataObject\ClassDefinition::getByName($name);
        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition::class, $class);

        $this->expectExceptionObject(new \RuntimeException('persistence reached'));

        $class->save(saveDefinitionFile: false);
    }

    public function testBlockLoadQuotesClassIdInTableName(): void
    {
        $realClassId = \Pimcore\Db::get()->fetchOne('SELECT id FROM classes ORDER BY CHAR_LENGTH(id), id LIMIT 1');
        $this->assertNotFalse($realClassId, 'The host needs at least one class definition.');

        $object = new \Pimcore\Model\DataObject\Concrete();
        $object->setId(1);
        $object->setClassId($realClassId . " UNION SELECT 'a:0:{}'#");

        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('oo_id');

        $this->expectException(\Doctrine\DBAL\Exception\TableNotFoundException::class);

        $block->load($object);
    }

    private function newClass(string $id, string $name): \Pimcore\Model\DataObject\ClassDefinition
    {
        $class = new \Pimcore\Model\DataObject\ClassDefinition();
        $class->setId($id);
        $class->setName($name);

        return $class;
    }
}
