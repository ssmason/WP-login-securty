<?php
/**
 * Tests shared by both mu-plugins.
 *
 * Every test narrates what it is doing with scenario() and step(), so the
 * console output reads like the comments in the plugin files.
 *
 * @package WP_Login_Security
 */

declare(strict_types=1);

use Brain\Monkey;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

abstract class PluginTestCase extends TestCase {

	protected const USER_ID  = 42;
	protected const PASSWORD = 'correct horse battery staple';

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	/**
	 * Print the heading for a test.
	 */
	protected function scenario( string $title ): void {
		fwrite( STDOUT, PHP_EOL . '● ' . $title . PHP_EOL );
	}

	/**
	 * Print one step of a test.
	 */
	protected function step( string $message ): void {
		fwrite( STDOUT, '    → ' . $message . PHP_EOL );
	}

	/**
	 * Print a passed check.
	 */
	protected function pass( string $message ): void {
		fwrite( STDOUT, '    ✔ ' . $message . PHP_EOL );
	}

	/**
	 * Make get_userdata() return a user whose stored login password is $user_pass.
	 */
	protected function given_user_with_hash( string $user_pass ): void {
		Functions\when( 'get_userdata' )->justReturn( (object) array( 'user_pass' => $user_pass ) );
	}

	/**
	 * Create an old WordPress phpass ($P$) hash.
	 */
	protected function legacy_hash( string $password ): string {
		$hasher = new PasswordHash( 8, true );

		return $hasher->HashPassword( $password ); // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
	}

	/**
	 * Create a native hash with deliberately weak settings, so it needs upgrading.
	 */
	protected function outdated_native_hash( string $password ): string {
		return password_hash( $password, PASSWORD_BCRYPT, array( 'cost' => 4 ) );
	}

	public function test_direct_access_is_blocked(): void {
		$this->scenario( 'STEP 1: Opening the file directly (without WordPress) is blocked' );

		$this->step( 'Running the plugin file in a fresh PHP process with no ABSPATH defined' );
		$code   = 'include ' . var_export( MU_PLUGIN_FILE, true ) . '; echo "LOADED";';
		$output = shell_exec( escapeshellarg( PHP_BINARY ) . ' -r ' . escapeshellarg( $code ) );

		$this->assertSame( '', (string) $output );
		$this->pass( 'The file exited immediately and nothing after it ran' );
	}

	public function test_new_hash_verifies_and_is_salted(): void {
		$this->scenario( 'wp_hash_password() creates a native hash' );

		$this->step( 'Hashing the same password twice' );
		$first  = wp_hash_password( self::PASSWORD );
		$second = wp_hash_password( self::PASSWORD );
		$this->step( 'Hash: ' . $first );

		$this->assertNotNull( password_get_info( $first )['algo'] );
		$this->pass( 'PHP recognises it as a native hash (' . password_get_info( $first )['algoName'] . ')' );

		$this->assertTrue( password_verify( self::PASSWORD, $first ) );
		$this->pass( 'password_verify() accepts the original password' );

		$this->assertNotSame( $first, $second );
		$this->pass( 'Each hash has its own random salt, so the two hashes differ' );
	}

	public function test_native_hash_with_correct_password(): void {
		$this->scenario( 'Login with a current native hash and the CORRECT password' );

		$hash = wp_hash_password( self::PASSWORD );
		$this->step( 'Stored hash is already native and up to date' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'Calling wp_check_password()' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted' );
		$this->pass( 'Hash was NOT rewritten (it is already current)' );
	}

	public function test_native_hash_with_wrong_password(): void {
		$this->scenario( 'Login with a native hash and the WRONG password' );

		$hash = $this->outdated_native_hash( self::PASSWORD );
		$this->step( 'Stored hash is native but outdated, so a correct login would upgrade it' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'Calling wp_check_password() with a wrong password' );
		$this->assertFalse( wp_check_password( 'wrong password', $hash, self::USER_ID ) );
		$this->pass( 'Login rejected' );
		$this->pass( 'Hash was NOT rewritten (only a correct password may trigger an upgrade)' );
	}

	public function test_outdated_native_hash_is_upgraded(): void {
		$this->scenario( 'Login with an OUTDATED native hash is upgraded' );

		$hash = $this->outdated_native_hash( self::PASSWORD );
		$this->step( 'Stored hash: ' . $hash . ' (bcrypt cost 4 - too weak)' );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->once()->with( self::PASSWORD, self::USER_ID );

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted' );
		$this->pass( 'wp_set_password() was called once to save a stronger hash' );
	}

	public function test_legacy_hash_is_migrated(): void {
		$this->scenario( 'MIGRATION: Login with a legacy MD5/phpass hash' );

		$hash = $this->legacy_hash( self::PASSWORD );
		$this->step( 'Stored hash: ' . $hash . ' (old WordPress phpass format)' );
		$this->assertNull( password_get_info( $hash )['algo'] );
		$this->pass( 'password_get_info() returns null, so the plugin uses the phpass fallback' );

		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->once()->with( self::PASSWORD, self::USER_ID );

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Login accepted by the legacy phpass checker' );
		$this->pass( 'wp_set_password() was called once to replace the old hash with a native one' );
	}

	public function test_legacy_hash_with_wrong_password(): void {
		$this->scenario( 'Login with a legacy hash and the WRONG password' );

		$hash = $this->legacy_hash( self::PASSWORD );
		$this->given_user_with_hash( $hash );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'Calling wp_check_password() with a wrong password' );
		$this->assertFalse( wp_check_password( 'wrong password', $hash, self::USER_ID ) );
		$this->pass( 'Login rejected' );
		$this->pass( 'Old hash left in place (no migration without the correct password)' );
	}

	public function test_legacy_application_password_does_not_overwrite_login_password(): void {
		$this->scenario( 'Application Password (legacy hash) never overwrites the login password' );

		$app_hash = $this->legacy_hash( 'app password' );
		$this->step( 'User login hash and app password hash are different' );
		$this->given_user_with_hash( wp_hash_password( self::PASSWORD ) );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'WordPress checks the app password with wp_check_password()' );
		$this->assertTrue( wp_check_password( 'app password', $app_hash, self::USER_ID ) );
		$this->pass( 'App password accepted' );
		$this->pass( 'wp_set_password() was NOT called, so the login password is safe' );
	}

	public function test_native_application_password_does_not_overwrite_login_password(): void {
		$this->scenario( 'Application Password (outdated native hash) never overwrites the login password' );

		$app_hash = $this->outdated_native_hash( 'app password' );
		$this->step( 'App password hash is outdated, which would normally trigger an upgrade' );
		$this->given_user_with_hash( wp_hash_password( self::PASSWORD ) );
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'WordPress checks the app password with wp_check_password()' );
		$this->assertTrue( wp_check_password( 'app password', $app_hash, self::USER_ID ) );
		$this->pass( 'App password accepted' );
		$this->pass( 'wp_set_password() was NOT called, so the login password is safe' );
	}

	public function test_no_user_id_skips_upgrade(): void {
		$this->scenario( 'Checking a password with no user ID' );

		$hash = $this->legacy_hash( self::PASSWORD );
		Functions\expect( 'get_userdata' )->never();
		Functions\expect( 'wp_set_password' )->never();

		$this->step( 'Calling wp_check_password() without a user ID' );
		$this->assertTrue( wp_check_password( self::PASSWORD, $hash ) );
		$this->pass( 'Password accepted' );
		$this->pass( 'No user was looked up and nothing was rewritten (there is no user to update)' );
	}

	public function test_check_password_filter_is_applied(): void {
		$this->scenario( 'Result passes through the check_password filter' );

		$hash = wp_hash_password( self::PASSWORD );
		$this->given_user_with_hash( $hash );

		$this->step( 'Hooking check_password so it forces a rejection' );
		Filters\expectApplied( 'check_password' )
			->once()
			->with( true, self::PASSWORD, $hash, self::USER_ID )
			->andReturn( false );

		$this->step( 'Calling wp_check_password() with the correct password' );
		$this->assertFalse( wp_check_password( self::PASSWORD, $hash, self::USER_ID ) );
		$this->pass( 'Filter received the real result and its answer was returned' );
	}
}
