package org.irmacard.crypto;

import org.irmacard.credentials.idemix.IdemixSystemParameters;

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
    }

    public BigInteger generateContext(){
        return new BigInteger(systemParameters.l_h, r);
    }

    public BigInteger generateNonce(){
        return new BigInteger(systemParameters.l_statzk, r);
    }
}
