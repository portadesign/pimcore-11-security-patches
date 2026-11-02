<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55634')]
final class FieldNameValidationTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'php injection' => ['foo;system()'],
            'constructor injection' => ['x;function __construct(){}//'],
            'backtick breakout' => ['poc` varchar(1), col `x'],
            'space' => ['a b'],
            'dash' => ['a-b'],
            'leading digit' => ['1field'],
            'newline' => ["field\nsecond"],
            'trailing newline' => ["field\n"],
            'dollar' => ['$field'],
            'too long' => [str_repeat('a', 64)],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validNameProvider(): array
    {
        return [
            'camel case' => ['myField'],
            'leading underscore' => ['_internal'],
            'single character' => ['a'],
            'digits and underscores' => ['field_123'],
            'maximum length' => [str_repeat('a', 63)],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testSetNameRejectsInvalidIdentifier(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName($name);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testClassificationstoreFieldSetNameRejectsInvalidIdentifier(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore())->setName($name);
    }

    public function testClassificationstoreFieldSetNameAcceptsValidIdentifier(): void
    {
        $field = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore())->setName('attributes');

        $this->assertSame('attributes', $field->getName());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('validNameProvider')]
    public function testSetNameAcceptsValidIdentifier(string $name): void
    {
        $field = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName($name);

        $this->assertSame($name, $field->getName());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testImportedLayoutRejectsInvalidFieldName(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        \Pimcore\Model\DataObject\ClassDefinition\Service::generateLayoutTreeFromArray(
            array: [
                'datatype' => 'layout',
                'fieldtype' => 'panel',
                'name' => 'Layout',
                'children' => [
                    [
                        'datatype' => 'data',
                        'fieldtype' => 'input',
                        'name' => $name,
                        'title' => 'Title',
                    ],
                ],
            ],
            throwException: true,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function classificationStoreKeyNameProvider(): array
    {
        return [
            'space' => ['Screen size'],
            'dash' => ['screen-size'],
            'leading digit' => ['1st key'],
            'umlaut' => ['Größe'],
            'long' => [str_repeat('a', 100)],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('classificationStoreKeyNameProvider')]
    public function testClassificationStoreKeyDefinitionKeepsFreeTextName(string $name): void
    {
        $definition = \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            definition: ['name' => $name, 'title' => 'Title', 'fieldtype' => 'input'],
            type: 'input',
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\Input::class, $definition);
        $this->assertSame($name, $definition->getName());
        $this->assertSame('Title', $definition->getTitle());
    }

    public function testClassificationStoreKeyDefinitionKeepsNameOfEncryptedDelegate(): void
    {
        $definition = \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            definition: [
                'name' => 'Secret key',
                'title' => 'Title',
                'fieldtype' => 'encryptedField',
                'delegateDatatype' => 'input',
                'delegate' => ['name' => 'Secret key', 'title' => 'Title', 'fieldtype' => 'input'],
            ],
            type: 'encryptedField',
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\EncryptedField::class, $definition);
        $this->assertSame('Secret key', $definition->getName());
        $this->assertSame('Secret key', $definition->getDelegate()?->getName());
    }

    public function testClassFieldNameWithSpaceIsStillRejectedNextToClassificationStoreKey(): void
    {
        \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            definition: ['name' => 'Screen size', 'fieldtype' => 'input'],
            type: 'input',
        );

        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName('Screen size');
    }

    public function testImportedLayoutKeepsValidFieldName(): void
    {
        $layout = \Pimcore\Model\DataObject\ClassDefinition\Service::generateLayoutTreeFromArray(
            array: [
                'datatype' => 'layout',
                'fieldtype' => 'panel',
                'name' => 'Layout',
                'children' => [
                    [
                        'datatype' => 'data',
                        'fieldtype' => 'input',
                        'name' => 'valid_field',
                        'title' => 'Title',
                    ],
                ],
            ],
            throwException: true,
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Layout\Panel::class, $layout);
        $this->assertSame('valid_field', $layout->getChildren()[0]->getName());
    }
}
