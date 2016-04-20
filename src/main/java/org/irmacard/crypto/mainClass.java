package org.irmacard.crypto;

import org.irmacard.credentials.idemix.IdemixPublicKey;

/**
 * Created by aredev on 20-4-16.
 */
public class mainClass {

    public static void main(String[] args) {
        String option = "c"; //args[0];

        if (option.equals("c")) {
            System.out.println(new challengeGenerator().generateContext());
            System.out.println(new challengeGenerator().generateNonce());
        }
    }
}
