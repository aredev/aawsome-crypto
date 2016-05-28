package org.irmacard.crypto;

import org.irmacard.credentials.idemix.proofs.ProofD;

import java.io.*;
import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by aredev on 20-4-16.
 */
public class verifier {

    private ProofD proof;
    private BigInteger c;
    private BigInteger A;
    private BigInteger eResponse;
    private BigInteger vResponse;
    private HashMap<Integer, BigInteger> aResponses;
    private HashMap<Integer, BigInteger> aDisclosed;
    private thesisParameters tp;

    public verifier() {
        tp = new thesisParameters();
        getProofValues();
        System.out.println(checkProof());
    }

    /**
     * Fill an hashmap given an input string as {1 = a1, 2 = a2, ..., n = an}
     * @param s
     * @param map
     */
    private void fillHashmap(String s, HashMap map){
        s = s.replace("}", "");
        s = s.replace("{",  "");
        String[] attributeIndexEls = s.split(",");
        for (String attributeIndex : attributeIndexEls){
            attributeIndex = attributeIndex.replaceAll(" ", "");
            String[] attributeEls = attributeIndex.split("=");
            map.put(Integer.parseInt(attributeEls[0]), new BigInteger(attributeEls[1]));
        }
    }

    /**
     * Get the values of the proof of knowledge from the received file
     * And also the disclosed attributes
     */
    private void getProofValues(){
        try{
            BufferedReader reader = new BufferedReader(new FileReader(new File("output.txt")));
            c = new BigInteger(reader.readLine());
            A = new BigInteger(reader.readLine());
            eResponse = new BigInteger(reader.readLine());
            vResponse = new BigInteger(reader.readLine());
            fillHashmap(reader.readLine(), aResponses = new HashMap<Integer, BigInteger>());
            //fillHashmap(reader.readLine(), aDisclosed = new HashMap<Integer, BigInteger>());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the challenges (nonce, context) from the textfile
     * @param  =
     * @return
     */
    private BigInteger getChallenges(int i){
        try{
            BufferedReader reader = new BufferedReader(new FileReader(new File("c.txt")));
            String a = reader.readLine();
            if (i == 0){
                //First line
                return new BigInteger(a);
            }
            else{
                //Second line
                return new BigInteger(reader.readLine());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * The disclosed attributes are written to file by hostAPD
     * The verification function needs to know, so we restore it from a file to an object.
     */
    private void restoreDisclosedAttributes(){
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File("disclosed.txt")));
            String line = reader.readLine();
            String[] attributes = line.split(",");
            for (int i = 0; i < attributes.length; i++){
                System.out.println(attributes[i]);
                aDisclosed.put(i, new BigInteger(attributes[i]));
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * If a user has passed through the Phase 1 check (check wheter the disclosed attributes are correct). Then
     * This part is called.
     * @return
     */
    public boolean checkProof(){
        restoreDisclosedAttributes();
        proof = new ProofD(c, A, eResponse, vResponse, aResponses, aDisclosed);
        return proof.verify(tp.getPk(), getChallenges(0), getChallenges(1));
    }
}
