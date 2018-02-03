<?php

namespace mgriego\Flysystem\ClamAV;

use League\Flysystem\AdapterInterface;
use League\Flysystem\Config;
use League\Flysystem\Util;
use Xenolope\Quahog\Client as ClamAvScanner;

class ClamAvScannerAdapter implements AdapterInterface
{
    const CONFIG_OPTIONS = [
        'scanOnCopy',
        'connectTimeout',
        'readTimeout',
        'failSilently',
    ];

    /**
     * @var \Xenolope\Quahog\Client
     */
    protected $scanner;

    /**
     * @var \League\Flysystem\AdapterInterface
     */
    protected $backingAdapter;

    /**
     * The connect URI for the clamd instance.  Possible values include:
     * "unix:///path/to/socket" and "tcp://IP-or-hostname:port-number"
     *
     * @var string
     */
    protected $scannerUri;

    /**
     * Whether to scan a file before copying it.
     *
     * @var boolean
     */
    protected $scanOnCopy;

    /**
     * @var integer
     */
    protected $connectTimeout = 30;

    /**
     * @var integer
     */
    protected $readTimeout = 30;

    /**
     * If true, a failure to connect to the configured clamd daemon will NOT
     * cause the operation to fail.  Otherwise, the default is to fail if the
     * file cannot be scanned due to a failure to connect.
     *
     * @var boolean
     */
    protected $failSilently;

    /**
     * Constructor
     *
     * @param \League\Flysystem\AdapterInterface $backingAdapter
     * @param string $scannerUri
     * @param array $options
     */
    public function __construct(AdapterInterface $backingAdapter, $scannerUri, $options = [])
    {
        $this->backingAdapter = $backingAdapter;
        $this->scannerUri = $scannerUri;

        foreach (self::CONFIG_OPTIONS as $option => $value) {
            if ($isset($options[$option])) {
                $this->$option = $value;
            }
        }
    }

    public function __construct(ClamAvScanner $scanner, AdapterInterface $backingAdapter, $scanOnCopy = false)
    {
        $this->scanner = $scanner;
        $this->scanOnCopy = $scanOnCopy;

        // Start a session so we can scan multiple files on the one socket.
        $this->scanner->startSession();
    }

    /**
     * Return the backing store adapter used by this adapter.
     *
     * @return \League\Flysystem\AdapterInterface
     */
    public function getBackingAdapter()
    {
        return $this->backingAdapter;
    }

    /**
     * Process the results from ClamAV to see if a virus was present.
     *
     * @param array $result
     * @param string $path
     * @throws VirusFoundException
     */
    protected function handleScannerResult($result, $path)
    {
        if ($result['status'] !== ClamAvScanner::RESULT_OK) {
            throw new VirusFoundException($path, $result['reason']);
        }
    }

    protected function connectToScanner()
    {
        // Set up socket
        // Connect with configured timeout
        // If exception and failSilently, catch it and return false
        // Otherwise rethrow exception or instantiate Quahog with the new socket and return the Quahog instance
        // Actually, handle the try/catch in scan/scanStream
    }

    /**
     * Scan the contents of a file for viruses.
     *
     * @param string $contents
     * @param string $path
     */
    protected function scan($contents, $path)
    {
        $this->handleScannerResult($this->scanner->scanStream($contents), $path);
    }

    /**
     * Scan a stream for viruses.
     *
     * @param resource $resource
     * @param string $path
     */
    protected function scanStream($resource, $path)
    {
        $result = $this->scanner->scanResourceStream($resource);
        rewind($resource);
        $this->handleScannerResult($result, $path);
    }

    /**
     * Return a seekable version of the passed stream.
     *
     * @param resource $resource
     * @return resource
     */
    protected function getSeekableStream($resource)
    {
        // If the stream isn't seekable, buffer it to a local temp file so
        // that we can rewind it when we're done scanning it.
        if (!Util::isSeekableStream($resource)) {
            $stream = fopen('php://temp', 'w+b');
            stream_copy_to_stream($resource, $stream);
            rewind($stream);
            return $stream;
        } else {
            return $resource;
        }
    }


    /**
     * Check whether a file exists.
     *
     * @param string $path
     *
     * @return array|bool|null
     */
    public function has($path)
    {
        return $this->backingAdapter->has($path);
    }

    /**
     * Read a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function read($path)
    {
        $result = $this->backingAdapter->read($path);

        if ($result !== false) {
            $this->scan($result, $path);
        }

        return $result;
    }

    /**
     * Read a file as a stream.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function readStream($path)
    {
        $result = $this->backingAdapter->readStream($path);

        if ($result !== false) {
            $result['stream'] = $this->getSeekableStream($result['stream']);
            $this->scanStream($result['stream'], $path);
        }

        return $result;
    }

    /**
     * List contents of a directory.
     *
     * @param string $directory
     * @param bool   $recursive
     *
     * @return array
     */
    public function listContents($directory = '', $recursive = false)
    {
        return $this->backingAdapter->listContents($directory, $recursive);
    }

    /**
     * Get all the meta data of a file or directory.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMetadata($path)
    {
        return $this->backingAdapter->getMetadata($path);
    }

    /**
     * Get the size of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getSize($path)
    {
        return $this->backingAdapter->getSize($path);
    }

    /**
     * Get the mimetype of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMimetype($path)
    {
        return $this->backingAdapter->getMimetype($path);
    }

    /**
     * Get the timestamp of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getTimestamp($path)
    {
        return $this->backingAdapter->getTimestamp($path);
    }

    /**
     * Get the visibility of a file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getVisibility($path)
    {
        return $this->backingAdapter->getVisibility($path);
    }

    /**
     * Write a new file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function write($path, $contents, Config $config)
    {
        $this->scan($contents, $path);
        return $this->backingAdapter->write($path, $contents, $config);
    }

    /**
     * Write a new file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function writeStream($path, $resource, Config $config)
    {
        $resource = $this->getSeekableStream($resource);
        $this->scanStream($resource, $path);
        return $this->backingAdapter->writeStream($path, $resource, $config);
    }

    /**
     * Update a file.
     *
     * @param string $path
     * @param string $contents
     * @param Config $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function update($path, $contents, Config $config)
    {
        $this->scan($contents, $path);
        return $this->backingAdapter->update($path, $contents, $config);
    }

    /**
     * Update a file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     * @param Config   $config   Config object
     *
     * @return array|false false on failure file meta data on success
     */
    public function updateStream($path, $resource, Config $config)
    {
        $resource = $this->getSeekableStream($resource);
        $this->scanStream($resource, $path);
        return $this->backingAdapter->updateStream($path, $resource, $config);
    }

    /**
     * Rename a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     */
    public function rename($path, $newpath)
    {
        return $this->backingAdapter->rename($path, $newpath);
    }

    /**
     * Copy a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     */
    public function copy($path, $newpath)
    {
        if ($this->scanOnCopy) {
            $this->readStream($path);
        }

        return $this->backingAdapter->copy($path, $newpath);
    }

    /**
     * Delete a file.
     *
     * @param string $path
     *
     * @return bool
     */
    public function delete($path)
    {
        return $this->backingAdapter->delete($path);
    }

    /**
     * Delete a directory.
     *
     * @param string $dirname
     *
     * @return bool
     */
    public function deleteDir($dirname)
    {
        return $this->backingAdapter->deleteDir($dirname);
    }

    /**
     * Create a directory.
     *
     * @param string $dirname directory name
     * @param Config $config
     *
     * @return array|false
     */
    public function createDir($dirname, Config $config)
    {
        return $this->backingAdapter->createDir($dirname, $config);
    }

    /**
     * Set the visibility for a file.
     *
     * @param string $path
     * @param string $visibility
     *
     * @return array|false file meta data
     */
    public function setVisibility($path, $visibility)
    {
        return $this->backingAdapter->setVisibility($path, $visibility);
    }
}
