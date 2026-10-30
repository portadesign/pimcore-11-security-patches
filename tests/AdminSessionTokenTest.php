<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-58401')]
final class AdminSessionTokenTest extends \PHPUnit\Framework\TestCase
{
    private const USERNAME = 'pd-sec-session-user';

    private \Pimcore\Model\User $user;

    protected function setUp(): void
    {
        $this->resetCanary();
        $this->deleteUser();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash('not-used', PASSWORD_DEFAULT),
            'active' => true,
        ]);
    }

    protected function tearDown(): void
    {
        $this->deleteUser();
        $this->resetCanary();
    }

    /**
     * @return array<string, array{class-string<\Symfony\Component\Security\Core\Authentication\Token\AbstractToken>}>
     */
    public static function legitimateTokenClassProvider(): array
    {
        return [
            'post authentication token' => [\Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken::class],
            'username password token' => [\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken::class],
            'two factor required token' => ['Pimcore\\Bundle\\AdminBundle\\Security\\Authentication\\Token\\TwoFactorRequiredToken'],
        ];
    }

    /**
     * @param class-string<\Symfony\Component\Security\Core\Authentication\Token\AbstractToken> $tokenClass
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('legitimateTokenClassProvider')]
    public function testLegitimateSessionTokenStillAuthenticates(string $tokenClass): void
    {
        $token = new $tokenClass(new \Pimcore\Security\User\User($this->user), 'pimcore_admin', []);

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken(serialize($token)));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    public function testBareForeignObjectInSessionIsRejected(): void
    {
        $payload = $this->serialized(fn (): mixed => $this->canary());

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($payload));

        $this->assertNull($authenticated);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the session token.');
    }

    public function testForeignObjectNestedInTokenAttributesIsNotInstantiated(): void
    {
        $token = new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(
            new \Pimcore\Security\User\User($this->user),
            'pimcore_admin',
            [],
        );
        $token->setAttribute('gadget', $this->canary());
        $payload = $this->serialized(fn (): mixed => $token);

        \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($payload));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the session token.');
    }

    private function requestWithSessionToken(string $serializedToken): \Symfony\Component\HttpFoundation\Request
    {
        $session = new \Symfony\Component\HttpFoundation\Session\Session(
            new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage(),
        );
        $session->set('_security_pimcore_admin', $serializedToken);

        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'pd-sec-session');

        return $request;
    }

    private function deleteUser(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }

    private function canary(): object
    {
        return new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary();
    }

    private function serialized(\Closure $factory): string
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized($factory);
    }

    private function resetCanary(): void
    {
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();
    }

    private function canaryExecutions(): int
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions;
    }
}
