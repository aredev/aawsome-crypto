package org.irmacard.crypto;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.*;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.info.InfoException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Created by aredev on 20-4-16.
 */
public class issuer {

    private IdemixPublicKey pk;
    private IdemixSecretKey sk;
    private List<BigInteger> attributes;
    private thesisParameters tp;

    public issuer() {
        tp = new thesisParameters();
        pk = tp.getPk();
        sk = tp.getSk();
        attributes = tp.getAttributes();

        IdemixCredential cd = null;
        try{
            cd = this.issueCredential();
            //ProofD proof = this.generateDisclosureProof(cd, Arrays.asList(1), new cha);
            //this.proofDToXml(proof);
        } catch (CredentialsException e) {
            e.printStackTrace();
        }
    }

    public void credentialToFile(IdemixCredential ic) {
        PrintWriter writer;
        try {
            writer = new PrintWriter("/home/aredev/Documents/credentials/credential.txt");
            writer.println(ic.getSignature().getA().toString());
            writer.println(ic.getSignature().get_e().toString());
            writer.println(ic.getSignature().get_v().toString());

            writer.println(ic.getPublicKey().getModulus().toString());
            writer.println(ic.getPublicKey().getGeneratorZ().toString());
            writer.println(ic.getPublicKey().getGeneratorS().toString());
            writer.println(ic.getPublicKey().getGeneratorsR().toString());

            writer.println(attributes.toString());
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }

    /**
     * Either returns the context or the nonce
     * @param i
     * @return
     */
    public BigInteger fromFileTo(int i){
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File("/home/aredev/Documents/credentials/challenge.xml")));
            BigInteger context = new BigInteger(reader.readLine().replace(" ", ""));
            if (i == 0){
                //Return the first line (ie. the context)
                return context;
            }else if (i == 1){
                //Return the second line (ie. the nonce)
                reader.readLine(); //Empty line
                return new BigInteger(reader.readLine());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public IdemixCredential fromFileToCredential() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(new File("/home/aredev/Documents/credentials/credential.txt")));

        BigInteger A = new BigInteger(reader.readLine());
        BigInteger e = new BigInteger(reader.readLine());
        BigInteger v = new BigInteger(reader.readLine());

        CLSignature signature = new CLSignature(A, e, v);

        BigInteger n = new BigInteger(reader.readLine());
        BigInteger Z = new BigInteger(reader.readLine());
        BigInteger S = new BigInteger(reader.readLine());

        String R = reader.readLine();
        R = R.replace("[", "");
        R = R.replace("]", "");
        String[] generators = R.split(",");
        BigInteger[] generatorsInt = new BigInteger[generators.length];
        for (int i = 0; i < generators.length; i++){
            generators[i] = generators[i].replace(" ", "");
            generatorsInt[i] = new BigInteger(generators[i]);
        }
        IdemixPublicKey publicKey = new IdemixPublicKey(n, Z, S, Arrays.asList(generatorsInt));

        String attr = reader.readLine();
        attr = attr.replace("[", "");
        attr = attr.replace("]", "");
        BigInteger attrNr = new BigInteger(attr);

        BufferedReader rdr = new BufferedReader(new FileReader(new File("/home/aredev/Documents/credentials/secret.txt")));
        BigInteger secret = new BigInteger(rdr.readLine());

        IdemixCredential ic = new IdemixCredential(publicKey, secret, Arrays.asList(attrNr), signature);
        return ic;
    }

    /**
     * Issue a credential
     */
    public IdemixCredential issueCredential() throws CredentialsException {
        Random r = new Random();
        IdemixSystemParameters parameters = pk.getSystemParameters();

        BigInteger context = new BigInteger(parameters.l_h, r);
        BigInteger n_1 = new BigInteger(parameters.l_statzk, r);
        BigInteger secret = new BigInteger(parameters.l_m, r);      //Value used for hiding and binding

        //Quick solution to save the secret
        try {
            PrintWriter writer = new PrintWriter("/home/aredev/Documents/credentials/secret.txt");
            writer.println(secret.toString());
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        CredentialBuilder builder = new CredentialBuilder(pk, attributes, context);
        IssueCommitmentMessage commitmentMessage = builder.commitToSecretAndProve(secret, n_1);     //Commit to secret value

        IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
        IssueSignatureMessage message = issuer.issueSignature(commitmentMessage, attributes, n_1);      //Make signature on attributes
        return builder.constructCredential(message);
    }

    /**
     * Generate proof of undisclosed attributes and has disclosed attributes
     * @param credential
     * @param indexes
     * @return
     */
    public ProofD generateDisclosureProof(IdemixCredential credential, List<Integer> indexes, BigInteger context, BigInteger nonce1){
        ProofD proof =  credential.createDisclosureProof(indexes, context, nonce1);
        System.out.println(proof.getDisclosedAttributes());

        return proof;
    }

    /**
     * Writes a proof to XML
     * @param proof
     * @throws ParserConfigurationException
     */
    public void proofDToXml(ProofD proof) throws ParserConfigurationException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document d = db.newDocument();
        Element rootElement = d.createElement("proof");
        d.appendChild(rootElement);

        Element proofC = d.createElement("c");
        proofC.appendChild(d.createTextNode(proof.get_c().toString()));
        rootElement.appendChild(proofC);

        Element proofA = d.createElement("A");
        proofA.appendChild(d.createTextNode(proof.getA().toString()));
        rootElement.appendChild(proofA);

        Element proofeResponse = d.createElement("e_resp");
        proofeResponse.appendChild(d.createTextNode(proof.get_e_response().toString()));
        rootElement.appendChild(proofeResponse);

        Element proofvResponse = d.createElement("v_resp");
        proofvResponse.appendChild(d.createTextNode(proof.get_v_response().toString()));
        rootElement.appendChild(proofvResponse);

        Element proofaResponses = d.createElement("a_resps");
        proofaResponses.appendChild(d.createTextNode(proof.get_a_responses().toString()));
        rootElement.appendChild(proofaResponses);

        Element proofaDisclosed = d.createElement("a_disc");
        proofaDisclosed.appendChild(d.createTextNode(proof.get_a_disclosed().toString()));
        rootElement.appendChild(proofaDisclosed);

        try {
            writeXml(d, "prooff");
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes XML to file
     * @param d
     * @throws TransformerException
     */
    private void writeXml(Document d, String name) throws TransformerException {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(d);

        StreamResult result = new StreamResult(new File("/home/aredev/Documents/credentials/" + name + ".xml"));
        transformer.transform(source, result);

        //StreamResult consoleResult = new StreamResult(System.out);
        //transformer.transform(source, consoleResult);
    }
}
