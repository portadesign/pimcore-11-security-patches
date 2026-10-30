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
