<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore\Exception;

use RuntimeException;

/**
 * @see https://developer.apple.com/documentation/appstoreserverapi/error_codes
 */
class ApiErrorException extends RuntimeException
{
}