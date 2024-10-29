<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore\Constants;

/**
 * A string that describes whether the transaction was purchased by the customer, or is available to them through Family Sharing.
 * 
 * @see https://developer.apple.com/documentation/appstoreserverapi/inappownershiptype
 */
enum InAppOwnershipType: string
{
    /**
     * The transaction belongs to the purchaser.
     */
    case Purchased = "PURCHASED";

    /**
     * The transaction belongs to a family member who benefits from service.
     */
    case FamilyShared = "FAMILY_SHARED";
}