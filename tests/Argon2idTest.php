<?php
/**
 * Argon2id.php specific tests. Shared tests live in PluginTestCase.
 *
 * @package WP_Login_Security
 */

declare(strict_types=1);

use Brain\Monkey\Functions;

final class Argon2idTest extends PluginTestCase {

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'PASSWORD_ARGON2ID' ) ) {
			$this->markTestSkipped( 'This PHP build has no Argon2id support.' );
		}
	}

	public function test_options_are_defined_in_one_place(): void {
		$this->scenario( 'STEP 2: mu_argon2id_options() returns the resource constraints' );

		$options = mu_argon2id_options();
		$this->step( 'memory_cost=' . $options['memory_cost'] . ' time_cost=' . $options['time_cost'] . ' threads=' . $options['threads'] );

		$this->assertSame(
			array(
				'memory_cost' => 65536,
				'time_cost'   => 4,
				'threads'     => 2,
			),
			$options
		);
		$this->pass( '64 MB RAM, 4 passes, 2 threads' );
	}

	public function test_hash_is_argon2id_with_plugin_options(): void {
		$this->scenario( 'STEP 3: wp_hash_password() uses Argon2id with the plugin options' );

		$hash = wp_hash_password( self::PASSWORD );
		$info = password_get_info( $hash );
		$this->step( 'Hash: ' . $hash );

		$this->assertSame( PASSWORD_ARGON2ID, $info['algo'] );
		$this->pass( 'Algorithm is Argon2id ($argon2id$)' );

		$this->assertSame( mu_argon2id_options(), $info['options'] );
		$this->pass( 'Options stored in the hash match mu_argon2id_options()' );
	}

	public function test_current_argon2id_hash_is_not_rehashed(): void {
		$this->scenario( 'REGRESSION: A current Argon2id hash is NOT rehashed on every login' );

		$hash = wp_hash_password( self::PASSWORD );
		$this->step( 'Stored hash uses threads=2, which differs from the PHP default of 1' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted' );
		$this->pass( 'Hash was NOT rewritten, because password_needs_rehash() gets the same options' );
	}

	public function test_argon2id_hash_with_old_options_is_upgraded(): void {
		$this->scenario( 'An Argon2id hash made with OLD settings is upgraded' );

		$hash = password_hash(
			self::PASSWORD,
			PASSWORD_ARGON2ID,
			array(
				'memory_cost' => 1024,
				'time_cost'   => 1,
				'threads'     => 1,
			)
		);
		$this->step( 'Stored hash: ' . $hash . ' (1 MB, 1 pass - too weak)' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->once()->with( self::PASSWORD, self::USER_ID );

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted' );
		$this->pass( 'wp_set_password() was called once to save a hash with the current settings' );
	}

	public function test_bcrypt_hash_is_upgraded_to_argon2id(): void {
		$this->scenario( 'A bcrypt hash is upgraded to Argon2id' );

		$hash = password_hash( self::PASSWORD, PASSWORD_BCRYPT );
		$this->step( 'Stored hash: ' . $hash . ' (bcrypt, e.g. from the fallback or Bcrypt.php)' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->once()->with( self::PASSWORD, self::USER_ID );

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted by password_verify()' );
		$this->pass( 'wp_set_password() was called once to switch the hash to Argon2id' );
	}
}
