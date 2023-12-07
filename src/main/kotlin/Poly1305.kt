object Poly1305 {
    const val CRYPTO_KEY_BYTES = 32
    const val CRYPTO_PASSWORD_BYTES = 16

    // Minimum USP (Uniformly Small Primes) for the key
    private val minUsp = intArrayOf(5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252)

    // Check if two hashes are the same
    private fun cryptoVerify(first: ByteArray, second: ByteArray): Int {
        var differentbits = 0
        for (i in 0..14)
            differentbits = differentbits or ((first[i].toInt() xor second[i].toInt()) and 0xff)

        return (1 and (differentbits - 1 ushr 8)) - 1
    }

    // Adds two arrays of integers and stores the result in the first array
    private fun add(currentHash: IntArray, currentChunk: IntArray) {
        var sum = 0
        var index = 0
        while (index < 17) {
            sum += currentHash[index] + currentChunk[index]
            currentHash[index] = sum and 255
            sum = sum ushr 8
            ++index
        }
    }

    // Reduces the size of an array of integers
    private fun squeeze(radix: IntArray) {
        var carrySum = 0

        for (index in 0..15) {
            carrySum += radix[index]
            radix[index] = carrySum and 255
            carrySum = carrySum ushr 8
        }

        carrySum += radix[16]
        radix[16] = carrySum and 3
        carrySum = 5 * (carrySum ushr 2)

        for (index in 0..15) {
            carrySum += radix[index]
            radix[index] = carrySum and 255
            carrySum = carrySum ushr 8
        }

        carrySum += radix[16]
        radix[16] = carrySum
    }

    // Finalizes a hash value
    private fun freeze(hash: IntArray) {
        val originalHash = IntArray(17)

        for (index in 0..16)
            originalHash[index] = hash[index]

        add(hash, minUsp)

        for (index in 0..16)
            hash[index] = hash[index] xor (-(hash[16] ushr 7) and (originalHash[index] xor hash[index]))
    }

    // Multiplies a hash value by a secret key in a way resistant to timing attacks
    private fun mulMod(hashValue: IntArray, secretKey: IntArray) {
        val tempHash = IntArray(17)

        for (index in 0..16) {
            var tempResult = 0
            for (i in 0..index) tempResult += hashValue[i] * secretKey[index - i]
            for (i in index + 1..16) tempResult += 320 * hashValue[i] * secretKey[index + 17 - i]
            tempHash[index] = tempResult
        }

        for (index in 0..16) hashValue[index] = tempHash[index]
        squeeze(hashValue)
    }

    fun hash(input: ByteArray, key: ByteArray): ByteArray {
        val result = ByteArray(CRYPTO_PASSWORD_BYTES)
        var size = input.size

        var offset = 0
        var counter = 0

        val secretKey = IntArray(17)
        val hash = IntArray(17)
        val coefficients = IntArray(17)

        secretKey[0] = key[0].toInt() and 0xFF
        secretKey[1] = key[1].toInt() and 0xFF
        secretKey[2] = key[2].toInt() and 0xFF
        secretKey[3] = key[3].toInt() and 15
        secretKey[4] = key[4].toInt() and 252
        secretKey[5] = key[5].toInt() and 0xFF
        secretKey[6] = key[6].toInt() and 0xFF
        secretKey[7] = key[7].toInt() and 15
        secretKey[8] = key[8].toInt() and 252
        secretKey[9] = key[9].toInt() and 0xFF
        secretKey[10] = key[10].toInt() and 0xFF
        secretKey[11] = key[11].toInt() and 15
        secretKey[12] = key[12].toInt() and 252
        secretKey[13] = key[13].toInt() and 0xFF
        secretKey[14] = key[14].toInt() and 0xFF
        secretKey[15] = key[15].toInt() and 15
        secretKey[16] = 0

        while (counter < 17) {
            hash[counter] = 0
            ++counter
        }

        while (size > 0) {
            counter = 0
            while (counter < 17) {
                coefficients[counter] = 0
                ++counter
            }

            counter = 0
            while (counter < 16 && counter < size) {
                coefficients[counter] = input[offset + counter].toInt() and 0xff
                ++counter
            }

            coefficients[counter] = 1
            offset += counter
            size -= counter

            add(hash, coefficients)
            mulMod(hash, secretKey)
        }

        freeze(hash)

        counter = 0
        while (counter < 16) {
            coefficients[counter] = key[counter + 16].toInt() and 0xFF
            ++counter
        }

        coefficients[16] = 0
        add(hash, coefficients)

        counter = 0
        while (counter < 16) {
            result[counter] = hash[counter].toByte()
            ++counter
        }

        return result
    }

    fun verify(
        hash: ByteArray,
        rawInput: ByteArray,
        key: ByteArray
    ): Boolean {
        val correct = hash(rawInput, key)
        return cryptoVerify(hash, correct) == 0
    }
}
