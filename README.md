# flysystem-clamav

[![Build Status](https://travis-ci.org/mgriego/flysystem-clamav.svg?branch=master)](https://travis-ci.org/mgriego/flysystem-clamav)

This package provides a filesystem adapter for
[Flysystem](https://github.com/thephpleague/flysystem) that scans files being
read from and written to an underlying filesystem using the popular
[ClamAV](https://www.clamav.net/) antivirus engine.  This adapter acts as a
passthrough adapter, sitting in between your application and whichever concrete
Flysystem adapter you use to store your files.  Since this scanner is itself a
Flysystem adapter, it can be implemented in an existing application simply by
dropping it in as a replacement to your existing Flysystem adapter so that all
filesytem calls go through the ClamAV adapter.  Simply pass your existing
adapter as the "backing" adapter to the ClamAV adapter when you instantiate it,
and the rest should be completely transparent to your application.

## Requirements
* [ClamAV](https://www.clamav.net/) - In order to utilize this package, you will need access to a running instance of the ClamAV `clamd` daemon.  This package utilizes `clamd` for its speed.  Other similar file scanning packages utilize `clamscan`, which requires reading and parsing the large virus database each time it is called.  The `clamd` daemon, on the other hand, only has to read and parse the database when it starts up and when the database is refreshed, making it a much faster option.  If you are utilizing [Docker](https://www.docker.com), then it is simple to get `clamd` up and running by utilizing one of the existing images from the [Docker Hub](https://hub.docker.com), such as the [infiniteproject/clamav](https://hub.docker.com/r/infiniteproject/clamav/) image.  Be sure that whichever image you use provides a running `clamd` daemon.  Images that simply run `clamscan` will not work with this adapter.
* [Flysystem](https://github.com/thephpleague/flysystem) - This package is a Flysystem filesystem adapter, so it goes without saying that you must be using Flysystem in your project either directly or via existing integrations (ie [Laravel](https://laravel.com)).  In order to utilize this adapter, you must also use a concrete adapter that stores and retrieves the files from a real filesystem.  If will be up to you as the developer (unless using an existing integration that provides the functionality for you) to set up the "backing" adapter and pass that adapter to the ClamAV adapter.

## Installation
Via composer:
```
composer require mgriego/flysystem-clamav
```

## Usage
In order to utilize this adapter, you must first set up your "backing" adapter
and an instance of [Quahog](https://github.com/jonjomckay/quahog) that points to
your `clamd` server.

First, set up your backing adapter like you would normally.  For instance, if
you are storing files using the `Local` adapter:
```
use League\Flysystem\Adapter\Local;

$backingAdapter = new Local(__DIR__.'/path/to/root');
```

Next, you must set up an instance of the Quahog ClamAV integration library.
Quahog is automatically installed by Composer when using this package, so there
is no need to require it explicitly.  More info on how to set up your Quahog
instance can be found in the
[Quahog README](https://github.com/jonjomckay/quahog).  If your `clamd` service
is running via TCP port 3310 on the local machine's loopback adapter, you can
instantiate Quahog like this:
```
use Socket\Raw\Factory as SocketFactory;
use Xenolope\Quahog\Client as ClamAVScanner;

// Create a new socket instance
$socket = (new SocketFactory())->createClient('tcp://127.0.0.1:3310');

// Create a new instance of the Client
$quahog = new ClamAVScanner($socket);
```

Once you have your backing adapter and scanner set up, you can instantiate this
adapter.  This adapter's constructor takes two required and one optional
arguments:
1. The Quahog instance
2. The backing adapter instance
3. A boolean telling the adapter whether to scan files that are being copied using the `copy` operation.  This parameter is optional and defaults to `false`.  If this is set to `true`, the adapter will first scan the source file before telling the backing adapter to perform the copy.

```
use League\Flysystem\Filesystem;
use mgriego\Flysystem\ClamAV\ClamAvScannerAdapter;

// In this case, copies will be scanned.
$adapter = new ClamAvScannerAdapter($quahog, $backingAdapter, true);
$filesystem = new Filesystem($adapter);
```

Files are scanned during the `read`/`readStream`, `write`/`writeStream`, and
`update`/`updateStream` operations.  If the adapter is configured as such, file
will also be scanned during the `copy` operation.  If ClamAV detects malware in
the file, a `\mgriego\Flysystem\ClamAV\VirusFoundException` exception will be
thrown.  The `getReason` method will return the name of the malware that was
detected in the file, and the `getPath` method will return the path of the file
that was being acted upon.  Or you can simply call the standard `getMessage`
method available on all Exceptions, and a message will be returned that contains
both the path and the name of the malware.

## Related packages
Coming soon!

## Acknowledgements
This package wouldn't be possible without these great projects:
* The [Quahog](https://github.com/jonjomckay/quahog) PHP library for integrating with ClamAV
* The [Flysystem](https://github.com/thephpleague/flysystem) filesystem abstraction library for PHP
* The [ClamAV](https://www.clamav.net/) antivirus engine
