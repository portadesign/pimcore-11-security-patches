<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class WordExportProbeController
{
    public const BODY = 'pd-sec-wordexport-body';

    public function renderAction(): \Symfony\Component\HttpFoundation\Response
    {
        return new \Symfony\Component\HttpFoundation\Response('<p>' . self::BODY . '</p>');
    }
}
