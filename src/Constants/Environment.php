<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore\Constants;

/**
 * @see https://developer.apple.com/documentation/storekit/appstore/environment
 */
enum Environment: string
{
    case Sandbox = "Sandbox";
    case Production = "Production";
    case Xcode = "Xcode";
}