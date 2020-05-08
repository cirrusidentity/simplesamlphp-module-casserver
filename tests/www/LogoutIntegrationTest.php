<?php

namespace Simplesamlphp\Casserver;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Test\BuiltInServer;

class LogoutIntegrationTest extends TestCase
{

    /** @var string $LOGOUT_URL */
    private static $LOGOUT_URL = '/module.php/casserver/logout.php';

    /**
     * @var \SimpleSAML\Test\BuiltInServer
     */
    protected $server;

    /**
     * @var string
     */
    protected $server_addr;

    /**
     * @var int
     */
    protected $server_pid;

    /**
     * @var string
     */
    protected $shared_file;

    /**
     * @var string
     */
    protected $cookies_file;

    /**
     * Setup the embedded server before every test
     * @return void
     */
    protected function setup(): void
    {
        $this->server = new BuiltInServer();
        $this->server_addr = $this->server->start();
        $this->server_pid = $this->server->getPid();
        $this->shared_file = sys_get_temp_dir() . '/' . $this->server_pid . '.lock';
        $this->cookies_file = sys_get_temp_dir() . '/' . $this->server_pid . '.cookies';
    }

    /**
     * The tear down method that is executed after all tests in this class.
     * Removes the lock file and cookies file
     * @return void
     */
    protected function tearDown(): void
    {
        @unlink($this->shared_file);
        @unlink($this->cookies_file); // remove it if it exists
        $this->server->stop();
    }

    /**
     * Test that for:
     * - no query params
     * - cas v2 url param
     * - invalid cas v2 service param
     * that the "you are logged out page is shown"
     * @dataProvider showLogoutPageProvider
     */
    public function testShowLoggedOutPage(array $queryParams, ?string $expectedLink)
    {

        /** @var array $resp */
        $resp = $this->server->get(
            self::$LOGOUT_URL,
            $queryParams,
            [
                CURLOPT_COOKIEJAR => $this->cookies_file,
                CURLOPT_COOKIEFILE => $this->cookies_file,
                CURLOPT_FOLLOWLOCATION => true
            ]
        );
        $this->assertEquals(200, $resp['code']);

        $this->assertStringContainsString(
            'You have been logged out. Thank you for using this service.',
            $resp['body'],
            'Logout with no, or invalid params should show logout page.'
        );
        if ($expectedLink) {
            $this->assertStringContainsString(
                '<p><a href="' . $expectedLink,
                $resp['body'],
                'Expect link to be shown'
            );
        } else {
            $this->assertStringNotContainsString(
                '<p><a href="',
                $resp['body'],
                'Expect no link to be shown'
            );
        }
    }

    public function showLogoutPageProvider(): array
    {
        return [
            // no params, no link expected
            [[], null],
            // invalid service ticket, no link expected
            [
                ['service' => 'http://not-legal.com'],
                null
            ],
            // invalid casv2, no link expected
            [
                ['url' => 'http://not-legal.com'],
                null
            ],
            // valid casv2
            [['url' => 'https://host2.domain:5678/path2/path3'], 'https://host2.domain:5678/path2/path3'],


        ];
    }


    public function testRedirectToCasV3Serivce()
    {
        $validServiceURl = 'https://override.example.com/abc';

        /** @var array $resp */
        $resp = $this->server->get(
            self::$LOGOUT_URL,
            [
                'service' => $validServiceURl
            ],
            [
                CURLOPT_COOKIEJAR => $this->cookies_file,
                CURLOPT_COOKIEFILE => $this->cookies_file,
                CURLOPT_FOLLOWLOCATION => false
            ]
        );
        $this->assertEquals(302, $resp['code']);

        $this->assertEquals(
            $validServiceURl,
            $resp['headers']['Location'],
            'Redirect to valid service url' . var_export($resp['headers'], true)
        );
    }
}
