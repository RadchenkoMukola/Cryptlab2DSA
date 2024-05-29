package org.example;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class DSA {

    // Оголошення константи для значення 1
    private static final BigInteger ONE = BigInteger.ONE;

    // Оголошення змінних для параметрів алгоритму DSA
    private BigInteger p, q, g, privateKey, publicKey;

    // Конструктор класу, що ініціалізує параметри
    public DSA() throws NoSuchAlgorithmException, InvalidKeySpecException {
        initializeParameters();
    }

    // Метод для ініціалізації параметрів алгоритму
    private void initializeParameters() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Генерація ключів
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        DSAPrivateKey priv = (DSAPrivateKey)pair.getPrivate();
        DSAPublicKey pub = (DSAPublicKey)pair.getPublic();

        // Встановлення приватного та публічного ключів
        privateKey = priv.getX();
        publicKey = pub.getY();

        // Отримання параметрів p, q, g
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        DSAPrivateKeySpec privSpec = keyFactory.getKeySpec(priv, DSAPrivateKeySpec.class);
        p = privSpec.getP();
        q = privSpec.getQ();
        g = privSpec.getG();
    }

    // Метод для підпису повідомлення
    public BigInteger[] sign(BigInteger message) {
        BigInteger k, r, s = BigInteger.ZERO;
        Random rnd = new Random();

        // Генерація підпису
        do {
            do {
                k = new BigInteger(160, rnd).mod(q.subtract(ONE)).add(ONE);
                r = g.modPow(k, p).mod(q);
            } while (r.equals(BigInteger.ZERO));

            try {
                s = (k.modInverse(q).multiply(message.add(privateKey.multiply(r)))).mod(q);
            } catch (ArithmeticException ignored) { }

        } while (s.equals(BigInteger.ZERO));

        return new BigInteger[]{r, s};
    }

    // Метод для перевірки підпису
    public boolean verify(BigInteger message, BigInteger[] signature) {
        BigInteger w, u1, u2, v;
        BigInteger r = signature[0], s = signature[1];

        // Перевірка чи r та s знаходяться в межах 0 і q
        if (r.compareTo(ONE) < 0 || r.compareTo(q) >= 0)
            return false;
        if (s.compareTo(ONE) < 0 || s.compareTo(q) >= 0)
            return false;

        // Обчислення допоміжних значень для перевірки
        w = s.modInverse(q);
        u1 = (message.multiply(w)).mod(q);
        u2 = (r.multiply(w)).mod(q);
        v = (g.modPow(u1, p).multiply(publicKey.modPow(u2, p)).mod(p)).mod(q);

        // Перевірка, чи v співпадає з r
        return v.equals(r);
    }

    // Метод для тестування реалізації алгоритму DSA
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Тестовий випадок для реалізації алгоритму DSA
        DSA dsa = new DSA();
        BigInteger message = new BigInteger("12345678901234567890");
        BigInteger[] signature = dsa.sign(message);
        System.out.println("Signature: " + signature[0] + ", " + signature[1]);
        boolean verifies = dsa.verify(message, signature);
        System.out.println("Signature verifies: " + verifies);

        BigInteger message2 = new BigInteger("98765432109876543210");
        verifies = dsa.verify(message2, signature);
        System.out.println("Signature verifies with different message: " + verifies);
    }
}
