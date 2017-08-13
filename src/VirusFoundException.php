<?php

namespace mgriego\Flysystem\ClamAV;

use League\Flysystem\Exception;
use Exception as BaseException;

class VirusFoundException extends Exception
{
    /**
     * @var string
     */
    protected $path;

    /**
     * @var string
     */
    protected $reason;

    /**
     * Constructor.
     *
     * @param string $path
     * @param string $reason
     * @param int $code
     * @param BaseException $previous
     */
    public function __construct($path, $reason, $code = 0, BaseException $previous = null)
    {
        $this->path = $path;
        $this->reason = $reason;

        parent::__construct('Found ' . $this->getReason() . ' when scanning ' . $this->getPath(), $code, $previous);
    }

    /**
     * Get the path that failed scanning.
     *
     * @return string
     */
    public function getPath()
    {
        return $this->path;
    }

    /**
     * Get the reson that scanning failed (ie virus name).
     *
     * @return string
     */
    public function getReason()
    {
        return $this->reason;
    }
}
