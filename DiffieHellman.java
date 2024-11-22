import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

    // Generate a large prime number p and base g for the Diffie-Hellman exchange
    public static BigInteger generatePrime(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger prime;
        do {
            prime = new BigInteger(bitLength, random);
        } while (!prime.isProbablePrime(100));
        return prime;
    }

    public static BigInteger generateBase(BigInteger p) {
        SecureRandom random = new SecureRandom();
        BigInteger g;
        do {
            g = new BigInteger(p.bitLength(), random);
        } while (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p) >= 0);
        return g;
    }

    // Alice's Side (Private key x, Public key A = g^x mod p)
    public static BigInteger alicePrivateKey(BigInteger p) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(p.bitLength(), random).mod(p.subtract(BigInteger.ONE));
    }

    // Bob's Side (Private key y, Public key B = g^y mod p)
    public static BigInteger bobPrivateKey(BigInteger p) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(p.bitLength(), random).mod(p.subtract(BigInteger.ONE));
    }

    // Calculate shared secret on Alice's side: sA = B^x mod p
    public static BigInteger calculateSharedSecretAlice(BigInteger B, BigInteger x, BigInteger p) {
        return B.modPow(x, p);
    }

    // Calculate shared secret on Bob's side: sB = A^y mod p
    public static BigInteger calculateSharedSecretBob(BigInteger A, BigInteger y, BigInteger p) {
        return A.modPow(y, p);
    }

    public static void main(String[] args) {
        // Step 1: Generate a large prime number p and base g
        int bitLength = 512; // The bit length of the prime number p
        BigInteger p = generatePrime(bitLength);
        BigInteger g = generateBase(p);

        System.out.println("Prime p: " + p);
        System.out.println("Base g: " + g);

        // Step 2: Alice and Bob generate their private keys
        BigInteger x = alicePrivateKey(p);  // Alice's private key
        BigInteger y = bobPrivateKey(p);    // Bob's private key

        System.out.println("Alice's private key (x): " + x);
        System.out.println("Bob's private key (y): " + y);

        // Step 3: Calculate public keys A and B
        BigInteger A = g.modPow(x, p);  // Alice's public key
        BigInteger B = g.modPow(y, p);  // Bob's public key

        System.out.println("Alice's public key (A): " + A);
        System.out.println("Bob's public key (B): " + B);

        // Step 4: Alice and Bob exchange public keys and compute the shared secret
        BigInteger secretAlice = calculateSharedSecretAlice(B, x, p);  // Alice calculates the shared secret
        BigInteger secretBob = calculateSharedSecretBob(A, y, p);      // Bob calculates the shared secret

        System.out.println("Alice's shared secret: " + secretAlice);
        System.out.println("Bob's shared secret: " + secretBob);

        // Step 5: Verify that both secrets match
        if (secretAlice.equals(secretBob)) {
            System.out.println("Shared secret match! The key exchange was successful.");
        } else {
            System.out.println("Error! The shared secrets do not match.");
        }
    }
}
