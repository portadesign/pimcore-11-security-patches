<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait AdminUserSession
{
    protected function authenticate(?\Pimcore\Model\User $user): void
    {
        $this->tokenStorage()->setToken(null === $user ? null : new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
            new \Pimcore\Security\User\User($user),
            'pimcore_admin',
            [],
        ));
    }

    protected function tokenStorage(): \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
    {
        $resolver = \Pimcore::getContainer()->get(\Pimcore\Security\User\TokenStorageUserResolver::class);

        return (new \ReflectionProperty($resolver, 'tokenStorage'))->getValue($resolver);
    }

    protected function deleteUserByName(string $name): void
    {
        $existing = \Pimcore\Model\User::getByName($name);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
