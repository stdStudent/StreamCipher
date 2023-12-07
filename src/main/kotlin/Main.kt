import java.security.SecureRandom

private fun testPasswordHashGeneration() {
    // Generate a key
    val key = ByteArray(Poly1305.CRYPTO_KEY_BYTES)
    SecureRandom().nextBytes(key)

    // Generate a password
    val password = "MyVeryStrongPassword123_МойОченьНадёжныйПароль123".toByteArray()

    // Notice that Poly1305 is not designed to hash passwords or secrets,
    // but rather to generate crypto-hashes that can be used for [H]MAC.
    // Source: https://crypto.stackexchange.com/questions/75762/why-not-use-chacha-derivatives-blake-rumba-to-make-an-hmac-for-use-with-cha/75772#75772

    // Hash the password. It's simply a proof of concept.
    val passwordHash = Poly1305.hash(password, key)

    // Verify password by hash
    val okHash = Poly1305.verify(passwordHash, password, key)
    if (okHash) {
        println("The hash is valid.")
    } else {
        println("The hash is invalid.")
    }

    // Some random hash
    val randHash = ByteArray(Poly1305.CRYPTO_PASSWORD_BYTES)
    SecureRandom().nextBytes(randHash)

    // If randHash != passwordHash, it won't pass
    val wrongHash = Poly1305.verify(randHash, password, key)
    if (wrongHash) {
        println("The hash is valid.")
    } else {
        println("The hash is invalid.")
    }
}

private fun testRandGen() {
    repeat(10) {
        val result = AdditiveRNG.rand(0, 255)
        if (result < 0 || result > 255) {
            println("Wrong.") // will never happen
        } else {
            println(result)
        }
    }
}

fun main() {
    testPasswordHashGeneration()
    testRandGen()
}
