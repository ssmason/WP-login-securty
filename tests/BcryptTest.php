<?php
/**
 * Bcrypt.php specific tests. Shared tests live in PluginTestCase.
 *
 * @package WP_Login_Security
 */

declare(strict_types=1);

final class BcryptTest extends PluginTestCase {

	public function test_hash_is_bcrypt(): void {
		$this->scenario( 'STEP 2: wp_hash_password() uses bcrypt' );

		$hash = wp_hash_password( self::PASSWORD );
		$this->step( 'Hash: ' . $hash );

		$this->assertSame( PASSWORD_BCRYPT, password_get_info( $hash )['algo'] );
		$this->pass( 'Algorithm is bcrypt ($2y$)' );

		$this->assertFalse( password_needs_rehash( $hash, PASSWORD_DEFAULT ) );
		$this->pass( 'Hash matches PASSWORD_DEFAULT, so it will not be rehashed on login' );
	}
}
