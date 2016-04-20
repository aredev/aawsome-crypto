package org.irmacard.crypto;

import org.irmacard.credentials.idemix.IdemixSystemParameters;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Random;

/**
 * Created by aredev on 20-4-16.
 */
public class challengeGenerator {

    private Random r;
    private thesisParameters parameters;
    private IdemixSystemParameters systemParameters;

    public challengeGenerator() {
        r = new Random();
        parameters = new thesisParameters();
        systemParameters = parameters.getPk().getSystemParameters();
        BigInteger context = new BigInteger(systemParameters.l_h, r);
        BigInteger nonce = new BigInteger(systemParameters.l_statzk, r);
        this.saveToFile(context, nonce);
    }

    /**
     * Writes random context and nonce a file
     * @param context
     * @param nonce
     */
    private void saveToFile(BigInteger context, BigInteger nonce){
        try {
            PrintWriter writer = new PrintWriter("c.txt");
            writer.println(context.toString());
            writer.println(nonce.toString());
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }
}
