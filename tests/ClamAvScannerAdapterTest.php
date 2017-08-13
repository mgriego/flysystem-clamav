<?php

namespace Tests;

use Mockery;
use PHPUnit\Framework\TestCase;
use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;
use League\Flysystem\Util;
use mgriego\Flysystem\ClamAV\ClamAvScannerAdapter;
use mgriego\Flysystem\ClamAV\VirusFoundException;
use Xenolope\Quahog\Client as ClamAvScanner;

class ClamAvScannerAdapterTest extends TestCase
{
    /**
     * @var League\Flysystem\AdapterInterface
     */
    protected $backingMock;

    /**
     * @var Xenolope\Quahog\Client
     */
    protected $scannerMock;

    /**
     * @var mgriego\Flysystem\ClamAV\ClamAvScannerAdapter
     */
    protected $adapter;

    /**
     * Set up for each test by creating the needed mocks and the adapter class.
     */
    public function setUp()
    {
        $this->backingMock = Mockery::mock(AdapterInterface::class);

        $this->scannerMock = Mockery::mock(ClamAvScanner::class);
        $this->scannerMock->shouldReceive('startSession');

        $this->adapter = new ClamAvScannerAdapter($this->scannerMock, $this->backingMock, false);
    }

    /**
     * Clean up after each test.
     */
    public function tearDown()
    {
        Mockery::close();
        unset($this->backingMock);
        unset($this->scannerMock);
        unset($this->adapter);
    }

    /**
     * Test the methods that simply pass through to the backing adapter.
     */
    public function testPassthroughMethodsWithSingleArgument()
    {
        $methods = [
            'has',
            'getMetadata',
            'getSize',
            'getMimetype',
            'getTimestamp',
            'getVisibility',
            'delete',
            'deleteDir',
        ];

        foreach ($methods as $method) {
            $this->backingMock->shouldReceive($method)->with('pathTestValue')->andReturn('responseTestValue');
        }

        // The scanner shouldn't be called at all for these methods.
        $this->scannerMock->shouldNotReceive('scanStream');
        $this->scannerMock->shouldNotReceive('scanResourceStream');

        // Ensure the response from the adapter matches the mocked response for
        // each method call.
        foreach ($methods as $method) {
            $this->assertEquals('responseTestValue', $this->adapter->{$method}('pathTestValue'));
        }
    }

    /**
     * Test passthrough to the listContents method.
     */
    public function testPassthroughToListContents()
    {
        $this->backingMock->shouldReceive('listContents')
            ->with('pathTestValue')
            ->andReturn('nonRecursiveResponse');

        $this->backingMock->shouldReceive('listContents')
            ->with('pathTestValue', false)
            ->andReturn('nonRecursiveResponse');

        $this->backingMock->shouldReceive('listContents')
            ->with('pathTestValue', true)
            ->andReturn('recursiveResponse');

        $this->assertEquals('nonRecursiveResponse', $this->adapter->listContents('pathTestValue'));
        $this->assertEquals('nonRecursiveResponse', $this->adapter->listContents('pathTestValue', false));
        $this->assertEquals('recursiveResponse', $this->adapter->listContents('pathTestValue', true));
    }

    /**
     * Test passthrough to the rename method.
     */
    public function testPassthroughToRename()
    {
        $this->backingMock->shouldReceive('rename')
            ->with('pathTestValue', 'newNameValue')
            ->andReturn('renameResponse');

        $this->assertEquals('renameResponse', $this->adapter->rename('pathTestValue', 'newNameValue'));
    }

    /**
     * Test passthrough to the setVisibility method.
     */
    public function testPassthroughToSetVisibility()
    {
        $this->backingMock->shouldReceive('setVisibility')
            ->with('pathTestValue', 'public')
            ->andReturn('setVisibilityResponse');

        $this->assertEquals('setVisibilityResponse', $this->adapter->setVisibility('pathTestValue', 'public'));
    }

    /**
     * Test passthrough to the createDir method.
     */
    public function testPassthroughToCreateDir()
    {
        $config = new Config();

        $this->backingMock->shouldReceive('createDir')
            ->with('pathTestValue', $config)
            ->andReturn('createDirResponse');

        $this->assertEquals('createDirResponse', $this->adapter->createDir('pathTestValue', $config));
    }

    /**
     * Test getting the backing adapter.
     */
    public function testGetBackingAdapter()
    {
        $this->assertEquals($this->backingMock, $this->adapter->getBackingAdapter());
    }

    /**
     * Test that read and readStream calls that return false don't call the
     * scanner and return false.
     */
    public function testNotFoundReads()
    {
        // The scanner shouldn't be called at all for these methods, since the
        // backing adapter should return false.
        $this->scannerMock->shouldNotReceive('scanStream');
        $this->scannerMock->shouldNotReceive('scanResourceStream');

        $this->backingMock->shouldReceive('read')
            ->with('nonExistantPath')
            ->andReturn(false);

        $this->backingMock->shouldReceive('readStream')
            ->with('nonExistantPath')
            ->andReturn(false);

        $this->assertEquals(false, $this->adapter->read('nonExistantPath'));
        $this->assertEquals(false, $this->adapter->readStream('nonExistantPath'));
    }

    /**
     * Ensure reads that aren't caught by the scanner return normally.
     */
    public function testReadsWithoutVirus()
    {
        $this->scannerMock->shouldReceive('scanStream')
            ->with('nonInfectedContents')
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('read')
            ->with('pathTestValue')
            ->andReturn('nonInfectedContents');

        $this->assertEquals('nonInfectedContents', $this->adapter->read('pathTestValue'));


        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');
        $response = ['stream' => $handle];

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('readStream')
            ->with('pathTestValue')
            ->andReturn($response);

        $this->assertEquals($response, $this->adapter->readStream('pathTestValue'));
        $this->assertEquals(0, ftell($handle));

        fclose($handle);
    }

    /**
     * Test a read that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testReadWithVirus()
    {
        $this->scannerMock->shouldReceive('scanStream')
            ->with('infectedContents')
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldReceive('read')
            ->with('pathTestValue')
            ->andReturn('infectedContents');

        $this->adapter->read('pathTestValue');
    }

    /**
     * Test reading a stream that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testReadStreamWithVirus()
    {
        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');
        $response = ['stream' => $handle];

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldReceive('readStream')
            ->with('pathTestValue')
            ->andReturn($response);

        $this->adapter->readStream('pathTestValue');

        fclose($handle);
    }

    /**
     * Ensure writes that aren't caught by the scanner return normally.
     */
    public function testWritesWithoutVirus()
    {
        $config = new Config();

        $this->scannerMock->shouldReceive('scanStream')
            ->with('nonInfectedContents')
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('write')
            ->with('pathTestValue', 'nonInfectedContents', $config)
            ->andReturn('writeResponse');

        $this->assertEquals('writeResponse', $this->adapter->write('pathTestValue', 'nonInfectedContents', $config));


        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('writeStream')
            ->with('pathTestValue', $handle, $config)
            ->andReturn('writeResponse');

        $this->assertEquals('writeResponse', $this->adapter->writeStream('pathTestValue', $handle, $config));

        fclose($handle);
    }

    /**
     * Test a write attempt that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testWriteWithVirus()
    {
        $config = new Config();

        $this->scannerMock->shouldReceive('scanStream')
            ->with('infectedContents')
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldNotReceive('write');

        $this->adapter->write('pathTestValue', 'infectedContents', $config);
    }

    /**
     * Test writing a stream that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testWriteStreamWithVirus()
    {
        $config = new Config();
        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldNotReceive('writeStream');

        $this->adapter->writeStream('pathTestValue', $handle, $config);

        fclose($handle);
    }

    /**
     * Ensure updates that aren't caught by the scanner return normally.
     */
    public function testUpdatesWithoutVirus()
    {
        $config = new Config();

        $this->scannerMock->shouldReceive('scanStream')
            ->with('nonInfectedContents')
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('update')
            ->with('pathTestValue', 'nonInfectedContents', $config)
            ->andReturn('updateResponse');

        $this->assertEquals('updateResponse', $this->adapter->update('pathTestValue', 'nonInfectedContents', $config));


        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('updateStream')
            ->with('pathTestValue', $handle, $config)
            ->andReturn('updateResponse');

        $this->assertEquals('updateResponse', $this->adapter->updateStream('pathTestValue', $handle, $config));

        fclose($handle);
    }

    /**
     * Test an update attempt that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testUpdateWithVirus()
    {
        $config = new Config();

        $this->scannerMock->shouldReceive('scanStream')
            ->with('infectedContents')
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldNotReceive('update');

        $this->adapter->update('pathTestValue', 'infectedContents', $config);
    }

    /**
     * Test updating a stream that contains malware caught by the scanner.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testUpdateStreamWithVirus()
    {
        $config = new Config();
        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldNotReceive('updateStream');

        $this->adapter->updateStream('pathTestValue', $handle, $config);

        fclose($handle);
    }

    /**
     * Test that copy doesn't scan when scanOnCopy is disabled.
     */
    public function testCopyWithoutScan()
    {
        $this->scannerMock->shouldNotReceive('scanResourceStream');

        $this->backingMock->shouldNotReceive('readStream');

        $this->backingMock->shouldReceive('copy')
            ->with('pathTestValue', 'newPathValue')
            ->andReturn('copyResponse');

        $this->assertEquals('copyResponse', $this->adapter->copy('pathTestValue', 'newPathValue'));
    }

    /**
     * Test that copy scans when scanOnCopy is enabled.
     */
    public function testCleanCopyWithScan()
    {
        $adapter = new ClamAvScannerAdapter($this->scannerMock, $this->backingMock, true);

        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');
        $response = ['stream' => $handle];

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('readStream')
            ->with('pathTestValue')
            ->andReturn($response);

        $this->backingMock->shouldReceive('copy')
            ->with('pathTestValue', 'newPathValue')
            ->andReturn('copyResponse');

        $this->assertEquals('copyResponse', $adapter->copy('pathTestValue', 'newPathValue'));
    }

    /**
     * Test that copy fails when scanOnCopy is enabled and malware is detected.
     *
     * @expectedException mgriego\Flysystem\ClamAV\VirusFoundException
     * @expectedExceptionMessage Found infectedContentsSignature when scanning pathTestValue
     */
    public function testInfectedCopyWithScan()
    {
        $adapter = new ClamAvScannerAdapter($this->scannerMock, $this->backingMock, true);

        $handle = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'testfile.txt', 'r');
        $response = ['stream' => $handle];

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with($handle)
            ->andReturn([
                'status' => ClamAvScanner::RESULT_FOUND,
                'reason' => 'infectedContentsSignature',
            ]);

        $this->backingMock->shouldReceive('readStream')
            ->with('pathTestValue')
            ->andReturn($response);

        $this->backingMock->shouldNotReceive('copy');

        $adapter->copy('pathTestValue', 'newPathValue');

        fclose($handle);
    }

    /**
     * Test that a non-seekable stream (Unix socket in this case) is buffered to
     * a seekable stream and that the seekable stream is returned.
     */
    public function testNonSeekableStreamRead()
    {
        list($readSocket, $writeSocket) = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        fwrite($writeSocket, 'nonInfectedContents');
        fclose($writeSocket);

        $this->scannerMock->shouldReceive('scanResourceStream')
            ->with(Mockery::any())
            ->andReturn(['status' => ClamAvScanner::RESULT_OK]);

        $this->backingMock->shouldReceive('readStream')
            ->with('pathTestValue')
            ->andReturn(['stream' => $readSocket]);

        $this->assertEquals(false, Util::isSeekableStream($readSocket));

        $response = $this->adapter->readStream('pathTestValue');

        $this->assertInternalType('resource', $response['stream']);
        $this->assertEquals(true, Util::isSeekableStream($response['stream']));
        $this->assertEquals(0, ftell($response['stream']));

        fclose($readSocket);
        fclose($response['stream']);
    }
}
