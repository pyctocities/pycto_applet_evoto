package com.pycto.applet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;

public class ApiPycto {
	public CSR request_cert = new CSR();
    public HttpClient client = new DefaultHttpClient();

	public boolean login(String user, String password){
		
		boolean result = false;
		
        try {
            HttpGet request = new HttpGet("http://localhost:8080/pycto/rest/api/login/"+user+"/"+password);
            HttpResponse response = client.execute(request);
            BufferedReader rd = new BufferedReader (new InputStreamReader(response.getEntity().getContent()));
            String line = rd.readLine();
			
			if(line.equals("Usuario y/o password incorrecto!")){
				result = false;
        	}			
			else
			{
				result = true;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		return result;
		  
	}
	
	
	public String pedir_firmar_CSR_cegado() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException{
		
		String certificado_cegado_firmado = null;
		
		RSAPublicKey pubKey;
		RSAPrivateKey privKey;

		//generate the RSA key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		//initialise the KeyGenerator with a random number.
		keyGen.initialize(1024, new SecureRandom());
		KeyPair keypair = keyGen.genKeyPair();
		
		privKey = (RSAPrivateKey)keypair.getPrivate();
		pubKey = (RSAPublicKey)keypair.getPublic();
		
		request_cert.setId(Integer.toString(1));
		request_cert.setPubKey(pubKey.getEncoded());
		
		Gson j = new Gson();
		String pseudonimo_sin_blindar = j.toJson(request_cert);

		String message = pseudonimo_sin_blindar;
		byte [] raw = message.getBytes("UTF8");

		BigInteger m = new BigInteger(raw);
		BigInteger e = pubKey.getPublicExponent();
		BigInteger d = privKey.getPrivateExponent();

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG","SUN");
		byte [] randomBytes = new byte[10];
		BigInteger r = null;
		BigInteger n = pubKey.getModulus();
		BigInteger gcd = null;
		BigInteger one = new BigInteger("1");
		
		//check that gcd(r,n) = 1 && r < n && r > 1
		do {
			random.nextBytes(randomBytes);
			r = new BigInteger(1, randomBytes);
			gcd = r.gcd(n);
			System.out.println("gcd: " + gcd);
		}
		while(!gcd.equals(one) || r.compareTo(n)>=0 || r.compareTo(one)<=0);

		//********************* CEGADO ************************************

		BigInteger pseudonimo_cegado = ((r.modPow(e,n)).multiply(m)).mod(n);
		System.out.println("\n Pseudonimo a enviar = " + pseudonimo_cegado);
		System.out.println("\n Pseudonimo a enviar en string= " + pseudonimo_cegado.toString());

		 try {
	            HttpGet request = new HttpGet("http://localhost:8080/pycto/rest/api/signcertificate/"+pseudonimo_cegado.toString());
	            HttpResponse response = client.execute(request);
	            BufferedReader rd = new BufferedReader (new InputStreamReader(response.getEntity().getContent()));
	            String line = rd.readLine();
				
				if(line.equals("No estas logueado, no puedes firmar el CSR")){
					certificado_cegado_firmado = "no se ha podido obtener el certificado";
	        	}			
				else
				{
					certificado_cegado_firmado = line;
				}
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		 
		return certificado_cegado_firmado;
		
	}
}
