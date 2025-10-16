/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.cs285_project;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class Server {
    public static void main(String[] args) {
        try {
            BigInteger prime = new BigInteger("24852977");
            BigInteger generator = new BigInteger("5");
            SecureRandom random = new SecureRandom();
            BigInteger privateKey = new BigInteger(32, random).mod(prime);
            BigInteger publicKey = generator.modPow(privateKey, prime);

            System.out.println("Server started. Waiting for client...");
            ServerSocket serverSocket = new ServerSocket(9806);
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            BigInteger clientPublicKey = new BigInteger(in.readLine());
            System.out.println("Received client's public key: " + clientPublicKey);

            out.println(publicKey);
            System.out.println("Sent public key to client: " + publicKey);

            BigInteger sharedSecret = clientPublicKey.modPow(privateKey, prime);

            BigInteger RSA_q = BigInteger.probablePrime(1024, random);
            BigInteger RSA_p = BigInteger.probablePrime(1024, random);
            BigInteger RSA_n = RSA_q.multiply(RSA_p);
            BigInteger RSA_tn = (RSA_p.subtract(BigInteger.ONE)).multiply(RSA_q.subtract(BigInteger.ONE));
            BigInteger RSA_e = BigInteger.valueOf(65537);

            while (RSA_tn.gcd(RSA_e).compareTo(BigInteger.ONE) > 0) {
                RSA_e = new BigInteger(RSA_tn.bitLength(), random);
                RSA_e = RSA_e.mod(RSA_tn.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            }

            BigInteger RSA_d = RSA_e.modInverse(RSA_tn);
            out.println(RSA_n + "," + RSA_e);
            System.out.println("Sent RSA public key to client: " + RSA_n + "," + RSA_e);

            String[] clientRSAKeys = in.readLine().split(",");
            BigInteger clientRSA_n = new BigInteger(clientRSAKeys[0]);
            BigInteger clientRSA_e = new BigInteger(clientRSAKeys[1]);
            System.out.println("Received client's RSA public key: " + clientRSA_n + "," + clientRSA_e);

            while (true) {
                BigInteger encryptedMessage = new BigInteger(in.readLine());
                String decryptedMessage = decryptRSA(encryptedMessage, RSA_d, RSA_n);
                System.out.println("Client: " + decryptedMessage);

                if (decryptedMessage.equalsIgnoreCase("exit")) {
                    break;
                }

                System.out.print("Server (you): ");
                BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
                String serverMessage = consoleReader.readLine();
                BigInteger encryptedServerMessage = encryptRSA(serverMessage, clientRSA_e, clientRSA_n);
                out.println(encryptedServerMessage);
                System.out.println("The encrypted message: " + encryptedServerMessage);

                if (serverMessage.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            in.close();
            out.close();
            socket.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static BigInteger encryptRSA(String message, BigInteger e, BigInteger n) {
        byte[] messageBytes = message.getBytes();
        BigInteger messageBigInt = new BigInteger(messageBytes);
        return messageBigInt.modPow(e, n);
    }

    private static String decryptRSA(BigInteger encryptedMessage, BigInteger d, BigInteger n) {
        BigInteger decryptedMessageBigInt = encryptedMessage.modPow(d, n);
        byte[] decryptedMessageBytes = decryptedMessageBigInt.toByteArray();
        return new String(decryptedMessageBytes);
    }
}

