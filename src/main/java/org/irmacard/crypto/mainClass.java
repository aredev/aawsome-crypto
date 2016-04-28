package org.irmacard.crypto;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.proofs.ProofD;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by aredev on 20-4-16.
 */
public class mainClass {

    /**
     * Generate jar with "gradle fatJar"
     * @param args
     */
    public static void main(String[] args) {
        String option = args[0];

        if (option.equals("c")) {
            //Generate a challenge
            new challengeGenerator();
        }else if (option.equals("p")){
            //Generate a proof
            issuer i = new issuer();
            try {
                IdemixCredential credential = i.fromFileToCredential();
                BigInteger context = i.fromFileTo(0);
                BigInteger nonce = i.fromFileTo(1);
                ProofD proof = i.generateDisclosureProof(credential, Arrays.asList(1, 2), context, nonce);
                i.proofDToXml(proof);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ParserConfigurationException e) {
                e.printStackTrace();
            }
        }else if (option.equals("i")){
            System.out.println("Issuing a credential");
            //issue a credential and writes to XML file
            issuer i = new issuer();
            try {
                System.out.println("Writing the credential to a file");
                i.credentialToFile(i.issueCredential());
            } catch (CredentialsException e) {
                e.printStackTrace();
            }
        }else if (option.equals("v")){
            //Verify the proof
            verifier v = new verifier();
        }
    }
}
