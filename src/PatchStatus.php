<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

enum PatchStatus
{
    case Applied;
    case Missing;
    case Unverified;
    case ToolsUnavailable;
}
