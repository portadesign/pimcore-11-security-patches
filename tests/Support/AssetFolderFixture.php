<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait AssetFolderFixture
{
    protected function createAssetFolder(int $parentId, string $filename): \Pimcore\Model\Asset\Folder
    {
        $folder = new \Pimcore\Model\Asset\Folder();
        $folder->setParentId($parentId);
        $folder->setFilename($filename);
        $folder->save(['versionNote' => __METHOD__ . ':' . __LINE__]);

        return $folder;
    }

    protected function deleteAssetByPath(string $path): void
    {
        $asset = \Pimcore\Model\Asset::getByPath($path);

        if ($asset instanceof \Pimcore\Model\Asset) {
            $asset->delete();
        }
    }
}
