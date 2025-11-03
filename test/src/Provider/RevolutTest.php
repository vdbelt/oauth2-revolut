<?php

namespace League\OAuth2\Client\Test\Provider;

use Exception;
use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\Revolut;
use League\OAuth2\Client\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\TestCase;

class RevolutTest extends TestCase
{
    protected $provider;

    protected function setUp() : void
    {
        $this->provider = new \League\OAuth2\Client\Provider\Revolut([
            'clientId' => 'mock.example',
            'privateKey' => 'file://' . __DIR__ . '/test_key.pem',
            'redirectUri' => 'https://example.com/callback-url'
        ]);
    }

    public function tearDown() : void
    {
        m::close();
        parent::tearDown();
    }

    public function testMissingPrivateKeyDuringInstantiationThrowsException()
    {
        $this->expectException(InvalidArgumentException::class);

        new \League\OAuth2\Client\Provider\Revolut([
            'clientId' => 'mock.example',
            'redirectUri' => 'https://example.com/callback-url'
        ]);
    }

    public function testPassPlainTextKey()
    {
        $provider = new Revolut([
            'privateKey' => 'mock_key'
        ]);

        $privateKey = $provider->getPrivateKey();

        $this->assertEquals('mock_key', $privateKey->contents());
    }

    public function testPassInstanceOfKey()
    {
        $key = InMemory::plainText('mock_key');

        $provider = new Revolut([
            'privateKey' => $key
        ]);

        $privateKey = $provider->getPrivateKey();

        $this->assertEquals('mock_key', $privateKey->contents());
    }

    public function testIsAbleToReadKeyFromFile()
    {
        $path = 'file://' . __DIR__ . '/test_key.pem';

        $provider = new Revolut([
            'privateKey' => $path
        ]);

        $privateKey = $provider->getPrivateKey();

        $this->assertEquals(file_get_contents($path), $privateKey->contents());
    }

    public function testSandbox()
    {
        $provider = new Revolut([
            'clientId' => 'mock_client_id',
            'privateKey' => 'mock_key',
            'redirectUri' => 'https://example.com/callback-url',
            'isSandbox' => true,
        ]);

        $authUrl = $provider->getAuthorizationUrl();
        $tokenUrl = $provider->getBaseAccessTokenUrl([]);

        $this->assertStringContainsString('https://sandbox-business.revolut.com', $authUrl);
        $this->assertStringContainsString('https://sandbox-b2b.revolut.com', $tokenUrl);
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/app-confirm', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/api/1.0/auth/token', $uri['path']);
    }

    /**
     * @throws IdentityProviderException
     */
    public function testGetAccessToken()
    {
        $provider = new Revolut([
            'clientId' => 'mock.example',
            'privateKey' => 'file://' . __DIR__ . '/test_key.pem',
            'redirectUri' => 'https://example.com/callback-url'
        ]);
        $provider = m::mock($provider);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => 'oa_sand_rqTQXDx4Wl72UDRShIhAIJColYASMZklLQVGA7lORWE',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'oa_sand_iPUCx_ZZ0koAW28A6rtL8rjwz5vjcsnjs-4DEEPjTEI'
            ])));
        $provider->setHttpClient($client);

        $token = $provider->getAccessToken('authorization_code', [
            'code' => 'hello-world'
        ]);

        $this->assertEquals($token->getToken(), 'oa_sand_rqTQXDx4Wl72UDRShIhAIJColYASMZklLQVGA7lORWE');
        $this->assertEquals($token->getRefreshToken(), 'oa_sand_iPUCx_ZZ0koAW28A6rtL8rjwz5vjcsnjs-4DEEPjTEI');
    }

    public function testNotImplementedGetResourceOwnerDetailsUrl()
    {
        $this->expectException(Exception::class);

        $this->provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'hello']));
    }

    public function testExceptionThrownWhenErrorObjectReceived()
    {
        $this->expectException(IdentityProviderException::class);
        $message = uniqid();
        $status = rand(400,600);
        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')
            ->andReturn(Utils::streamFor('{"error_description": "'.$message.'","code": '.$status.'}'));
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $postResponse->shouldReceive('getReasonPhrase');
        $postResponse->shouldReceive('getStatusCode')->andReturn($status);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($postResponse);
        $this->provider->setHttpClient($client);
        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }
}
