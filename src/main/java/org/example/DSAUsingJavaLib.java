package org.example;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class DSAUsingJavaLib {

    public static void main(String[] args) throws Exception {
        // Тестовий випадок для реалізації алгоритму DSA з використанням інструментів бібліотеки Java
        // Генерація ключів
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        // Підготовка до підпису повідомлення
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(priv);
        String str = "This is a string to sign";
        byte[] strByte = str.getBytes(StandardCharsets.UTF_8);
        dsa.update(strByte);

        // Генерація підпису
        byte[] realSig = dsa.sign();

        System.out.println("Signature: " + Base64.getEncoder().encodeToString(realSig));

        // Підготовка до перевірки підпису
        dsa.initVerify(pub);
        dsa.update(strByte);

        // Перевірка підпису
        boolean verifies = dsa.verify(realSig);
        System.out.println("Signature verifies: " + verifies);
    }
}