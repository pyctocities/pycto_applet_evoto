package com.pycto.applet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;

public class ApiPycto {
	public CSR request_cert = new CSR();
	public HttpClient client = new DefaultHttpClient();
	
	public String URL_BASE="http://localhost:8080/pycto/rest/api/";
	//Para HTTPS se tendra que utilizar la siguiente URL
	//public String URL_BASE="https://localhost:8081/pycto/rest/api/";   


	public boolean login(String user, String password){

		boolean result = false;

		try {
			
			HttpGet request = new HttpGet(URL_BASE+"login/"+user+"/"+password);
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


	public String pedir_firmar_CSR_cegado(String username,RSAPrivateKey privKey,RSAPublicKey pubKey) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException{
		
		String certificado_cegado_firmado = null;

		request_cert.setId(username);
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

		MessageDigest md = null;
		BigInteger pseudonim_cegado2 = null;
		
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(pseudonimo_sin_blindar.getBytes());
			byte[] passbytes = md.digest();
			pseudonim_cegado2 = new BigInteger(1,passbytes);
			
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		
		BigInteger pseudonimo_cegado = pseudonim_cegado2.multiply(new BigInteger("1111111111111111111111111111"));
		
		System.out.println("Pseudonim abans de firmar: "+pseudonimo_cegado);


		try {
			System.out.println(URL_BASE+"signcertificate/"+pseudonimo_cegado.toString());
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

	public String vote(String pepina) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException{
		String line="";
		String url = URL_BASE+"vote/"+URLEncoder.encode(pepina);
		System.out.println("URL: "+url);
		try {
			HttpGet request = new HttpGet(url);
			HttpResponse response = client.execute(request);
			BufferedReader rd = new BufferedReader (new InputStreamReader(response.getEntity().getContent()));
			line = rd.readLine();

			//				if(line.equals("No estas logueado, no puedes firmar el CSR")){
			//					certificado_cegado_firmado = "no se ha podido obtener el certificado";
			//	        	}			
			//				else
			//				{
			//					certificado_cegado_firmado = line;
			//				}

		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		return line;

	}	
}
