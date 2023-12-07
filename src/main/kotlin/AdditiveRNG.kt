import kotlin.math.absoluteValue
import kotlin.random.Random

object AdditiveRNG {
    private var seed: Long
    private val a: Long
    private val c: Long
    private val m: Long

    init {
        seed = Random.nextLong()
        a = Random.nextLong(1, Long.MAX_VALUE)
        c = Random.nextLong(0, Long.MAX_VALUE)
        m = Random.nextLong(1, Long.MAX_VALUE)
    }

    fun rand(startInt: Long, endInt: Long): Long {
        // X_{n+1} = (a*X_n + c) mod m
        seed = (a * seed + c) % m
        return startInt + (seed.absoluteValue % (endInt - startInt + 1))
    }
}