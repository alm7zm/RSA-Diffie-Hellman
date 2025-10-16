/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.cs285_project;


import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

public class Client {
    public static void main(String[] args) {
        try {
            // Shared values (must be the same for both client and server)
            BigInteger prime = new BigInteger("24852977"); // Example large prime
            BigInteger generator = new BigInteger("5"); // Chosen generator

            // Generate a random private key
            SecureRandom random = new SecureRandom();
            BigInteger privateKey = new BigInteger(32, random).mod(prime);

            // Calculate public key: (generator ^ privateKey) % prime
            BigInteger publicKey = generator.modPow(privateKey, prime);

            System.out.println("Client started");
            Socket socket = new Socket("localhost", 9806);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Send public key to server
            out.println(publicKey);
            System.out.println("Sent public key to server: " + publicKey);

            // Receive server's public key
            BigInteger serverPublicKey = new BigInteger(in.readLine());
            System.out.println("Received server's public key: " + serverPublicKey);

            // Compute shared secret: (serverPublicKey ^ privateKey) % prime
            BigInteger sharedSecret = serverPublicKey.modPow(privateKey, prime);
            
            //RSA part 
            //genarate 2 random  prime (ADDED CLIENT RSA KEYS)
            BigInteger RSA_q=BigInteger.probablePrime(1024, random);
            BigInteger RSA_p=BigInteger.probablePrime(1024, random);
            //multiply
            BigInteger RSA_n=RSA_q.multiply(RSA_p);
            //(p-1)*(q-1)
            BigInteger RSA_tn=(RSA_p.subtract(BigInteger.ONE)).multiply(RSA_q.subtract(BigInteger.ONE));
            //select e
            BigInteger RSA_e=BigInteger.valueOf(65537);
            // make sure that e is working (valid)
            while (RSA_tn.gcd(RSA_e).compareTo(BigInteger.ONE) > 0) {
                // Try another random e (if necessary)
                RSA_e = new BigInteger(RSA_tn.bitLength(), random);
                // Ensure e is between 2 and RSA_tn
                RSA_e = RSA_e.mod(RSA_tn.subtract(BigInteger.TWO)).add(BigInteger.TWO);    
            }
            // e inverse mod tn
            BigInteger RSA_d =RSA_e.modInverse(RSA_tn);
            //public key = (e,n) to encyript
            //rule is (Original_messege power(e)) mod n 
            //private key =(d,n) to decripyt 
            //rule is (encrpted_messege power(d)) mod n 
            
            // Send client's RSA public key to server (ADDED)
            out.println(RSA_n + "," + RSA_e);
            
            // Receive server's RSA public key
            String[] serverRSA = in.readLine().split(",");
            BigInteger serverRSA_n = new BigInteger(serverRSA[0]);
            BigInteger serverRSA_e = new BigInteger(serverRSA[1]);
            System.out.println("Received server's RSA public key: (n, e) = (" + serverRSA_n + ", " + serverRSA_e + ")");
            
            //read input from the keyboard 
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            while (true) {
                System.out.print("Enter message to send: ");
                String message = userInput.readLine();

                if (message.equalsIgnoreCase("exit")) {
                    // Encrypt and send exit message (MODIFIED)
                    BigInteger encryptedMessage = encryptRSA(message, serverRSA_e, serverRSA_n);
                    out.println(encryptedMessage);
                    break; 
                }

                // Encrypt and send the message (MODIFIED)
                BigInteger encryptedMessage = encryptRSA(message, serverRSA_e, serverRSA_n);
                System.out.println("the encrypted Message is: "+ encryptedMessage);
                out.println(encryptedMessage);

                // Receive and decrypt server response (ADDED)
                String serverResponse = in.readLine();
                if (serverResponse == null) break;
                BigInteger encryptedResponse = new BigInteger(serverResponse);
                String decryptedResponse = decryptRSA(encryptedResponse, RSA_d, RSA_n);
                System.out.println("Server says: " + decryptedResponse);
            }

            // Close resources
            in.close();
            out.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static BigInteger encryptRSA(String message, BigInteger e, BigInteger n) {
        byte[] messageBytes = message.getBytes();
        BigInteger messageBigInt = new BigInteger(messageBytes);
        return messageBigInt.modPow(e, n);
    }
    
    // ADDED (but kept outside main to preserve structure)
    private static String decryptRSA(BigInteger encryptedMessage, BigInteger d, BigInteger n) {
        BigInteger decryptedMessageBigInt = encryptedMessage.modPow(d, n);
        byte[] decryptedMessageBytes = decryptedMessageBigInt.toByteArray();
        return new String(decryptedMessageBytes);
    }
}