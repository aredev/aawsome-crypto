package org.irmacard.crypto;

import org.irmacard.credentials.idemix.proofs.ProofD;

import java.io.*;
import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by aredev on 20-4-16.
 */
public class verifier {

    ProofD proof;
    BigInteger c;
    BigInteger A;
    BigInteger eResponse;
    BigInteger vResponse;
    HashMap<Integer, BigInteger> aResponses;
    HashMap<Integer, BigInteger> aDisclosed;
    thesisParameters tp;

    public verifier() {
        tp = new thesisParameters();
        getProofValues();
        System.out.println(checkProof());
    }

    /**
     * Todo: Make it work for arbitrary length strings
     * @param s
     */
    private void fillHashmap(String s, HashMap map){
        s = s.replace("}", "");
        s = s.replace("{",  "");
        String[] els = s.split("=");
        map.put(Integer.parseInt(els[0]), new BigInteger(els[1]));
    }

    private void getProofValues(){
        try{
            BufferedReader reader = new BufferedReader(new FileReader(new File("/home/aredev/Documents/output.txt")));
            String line;
            c = new BigInteger(reader.readLine());
            A = new BigInteger(reader.readLine());
            eResponse = new BigInteger(reader.readLine());
            vResponse = new BigInteger(reader.readLine());
            fillHashmap(reader.readLine(), aResponses = new HashMap<Integer, BigInteger>());
            fillHashmap(reader.readLine(), aDisclosed = new HashMap<Integer, BigInteger>());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public boolean checkProof(){
        proof = new ProofD(c, A, eResponse, vResponse, aResponses, aDisclosed);
        System.out.println(tp.getNonce());
        //return proof.verify(tp.getPk(), tp.getContext(), tp.getNonce());
        return true;
    }
}
