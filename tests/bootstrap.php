<?php
/**
 * Test bootstrap.
 *
 * Loads ONE mu-plugin (chosen by the MU_PLUGIN environment variable) without a
 * WordPress install. WordPress functions the plugins call are mocked per test
 * with Brain Monkey.
 *
 * @package WP_Login_Security
 */

declare(strict_types=1);

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// STEP 1: Pretend to be WordPress so the plugin's direct-access guard lets it load.
// tests/wp/wp-includes/class-phpass.php is the real legacy hasher copied from WordPress core.
define( 'ABSPATH', __DIR__ . '/wp/' );
define( 'WPINC', 'wp-includes' );

// STEP 2: Load the legacy phpass class so tests can create old-style $P$ hashes.
require_once ABSPATH . WPINC . '/class-phpass.php';

// STEP 3: Load the plugin under test.
$mu_plugin = getenv( 'MU_PLUGIN' );

if ( false === $mu_plugin || ! in_array( $mu_plugin, array( 'Bcrypt', 'Argon2id' ), true ) ) {
	fwrite( STDERR, 'Set MU_PLUGIN to Bcrypt or Argon2id. Run "composer test".' . PHP_EOL );
	exit( 1 );
}

define( 'MU_PLUGIN_FILE', dirname( __DIR__ ) . '/' . $mu_plugin . '.php' );

require_once MU_PLUGIN_FILE;
require_once __DIR__ . '/PluginTestCase.php';

fwrite( STDOUT, PHP_EOL . '=== Testing ' . $mu_plugin . '.php ===' . PHP_EOL );
