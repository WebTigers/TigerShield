<?php
// SPDX-License-Identifier: LicenseRef-TigerShield-Proprietary
// Copyright (c) 2026 K. Beau Beauchamp / WebTigers. All rights reserved.
// PROPRIETARY & CONFIDENTIAL — commercial license only. NOT open source.

namespace TigerShield\Tests\Unit;

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Zend_Controller_Front;
use Zend_Controller_Plugin_Abstract;

/**
 * The firewall plugin used to pin stack slot 5. Plugins registered without an index fill 0,1,2,… in module-load
 * order, so on an install where six had loaded before TigerShield, Zend threw "Plugin with stackIndex 5 already
 * registered" at boot — every request 500'd (seen on the dev control plane, 2026-11-17).
 */
final class FirewallRegistrationTest extends TestCase
{
    #[RunInSeparateProcess]
    public function testItRegistersInAFreeSlotWhenSlotFiveIsTaken(): void
    {
        require_once dirname(__DIR__, 2) . '/Bootstrap.php';
        $front = Zend_Controller_Front::getInstance();
        $front->resetInstance();
        for ($i = 0; $i < 6; $i++) {   // six modules' plugins, auto-numbered 0..5
            $front->registerPlugin(new class extends Zend_Controller_Plugin_Abstract {});
        }

        \Tigershield_Bootstrap::registerFirewall($front);
        \Tigershield_Bootstrap::registerFirewall($front);   // a second bootstrap pass is a no-op

        $firewalls = array_filter($front->getPlugins(), static fn ($p) => $p instanceof \Tigershield_Plugin_Firewall);
        $this->assertCount(1, $firewalls, 'registered exactly once, in a free slot');
        $this->assertCount(7, $front->getPlugins());
    }
}
