<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class PatchInspectionGuardTest extends \PHPUnit\Framework\TestCase
{
    public function testAllPatchesVerifiedAndApplied(): void
    {
        $this->guard()->assertApplied(inspection: ['checked' => 3, 'missing' => []], patchesExpected: true, output: 'out');

        $this->addToAssertionCount(1);
    }

    public function testSingleVerifiedPatchIsAccepted(): void
    {
        $this->guard()->assertApplied(inspection: ['checked' => 1, 'missing' => []], patchesExpected: true, output: 'out');

        $this->addToAssertionCount(1);
    }

    public function testNothingToVerifyWithoutExpectedPatches(): void
    {
        $this->guard()->assertApplied(inspection: ['checked' => 0, 'missing' => []], patchesExpected: false, output: 'out');

        $this->addToAssertionCount(1);
    }

    public function testNoVerifiedPatchWhilePatchesAreExpectedThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("No patch could be verified after re-applying (neither patch nor git available, or patch files not retrievable). Output of the patches commands:\nchild output");

        $this->guard()->assertApplied(inspection: ['checked' => 0, 'missing' => []], patchesExpected: true, output: 'child output');
    }

    public function testMissingPatchesThrowWithCountsAndOutput(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Patches still missing after re-applying (2 in vendor/one, 1 in vendor/two). Output of the patches commands:\nchild output");

        $this->guard()->assertApplied(
            inspection: ['checked' => 5, 'missing' => ['vendor/one' => 2, 'vendor/two' => 1]],
            patchesExpected: true,
            output: 'child output',
        );
    }

    public function testMissingPatchesAreReportedEvenWhenNoneWereExpected(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Patches still missing after re-applying (1 in vendor/one)');

        $this->guard()->assertApplied(inspection: ['checked' => 1, 'missing' => ['vendor/one' => 1]], patchesExpected: false, output: '');
    }

    public function testInspectionWithoutPatchAndGitIsNotAccepted(): void
    {
        $patch = new \cweagans\Composer\Patch();
        $patch->package = 'vendor/one';
        $patch->description = 'test';
        $patch->url = 'https://example.test/patches/a.patch';
        $patch->localPath = '/p/a.patch';
        $inspector = new \Portadesign\PimcoreSecurityPatches\InstalledPatchInspector(
            runner: new PatchlessProcessRunner(inner: new RecordingProcessRunner(exitCodes: ['git' => 127])),
            download: static function (): void {
            },
            io: new \Composer\IO\BufferIO(),
            bundledDirectory: sys_get_temp_dir(),
        );

        $inspection = $inspector->inspectAll(targets: ['vendor/one' => ['installPath' => '/install/one', 'patches' => [$patch]]]);

        self::assertSame(0, $inspection['checked']);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('No patch could be verified after re-applying');

        $this->guard()->assertApplied(inspection: $inspection, patchesExpected: true, output: '');
    }

    private function guard(): \Portadesign\PimcoreSecurityPatches\PatchInspectionGuard
    {
        return new \Portadesign\PimcoreSecurityPatches\PatchInspectionGuard();
    }
}
