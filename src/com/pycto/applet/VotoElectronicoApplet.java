package com.pycto.applet;
import java.applet.Applet;
import java.awt.Graphics;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.google.gson.Gson;


public class VotoElectronicoApplet extends Applet {
	
		public CSR request_cert = new CSR();
	
		@Override
		public void start() {
			// TODO Auto-generated method stub
			super.start();
			
			try {
				//Empieza aqui: Generamos a partir de keytool de java las claves publicas y privadas
				
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
				
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
				keyGen.initialize(1024, random);
				
				KeyPair pair = keyGen.generateKeyPair();
				PrivateKey priv = pair.getPrivate();
				PublicKey pub = pair.getPublic();
				
				//Acaba aqui: Generamos a partir de keytool de java las claves publicas y privadas

				//Los guardamos en la clase CSR
				//System.out.println("La clave privada es: "+priv.getEncoded());
				System.out.println("La clave publica es: "+pub.getEncoded());
				
				request_cert.setId(Integer.toString(1));
				request_cert.setPubKey(pub.getEncoded());
				
				//Pasamos a JSON el CSR (id+pubkey)
				Gson j = new Gson();
				String csr = j.toJson(request_cert);
				
				System.out.println("El json es: "+csr);
				//Hacemos hash del CSR
				MessageDigest cript = MessageDigest.getInstance("SHA-1");
				cript.reset();
				cript.update(csr.getBytes());
				byte[] CsrHashed = cript.digest();
				//Aqui se tendria que hacer la modificacion del cegado...como? (linea temporal)
				
				byte[] CsrHashedBlinded = CsrHashed;


			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
		}
		
		@Override
		public void paint(Graphics g) {
		// TODO Auto-generated method stub
		super.paint(g);
		g.drawBytes(request_cert.pubKey, 0, request_cert.pubKey.length, 10, 30);
	    g.drawString (request_cert.pubKey.toString(), 20, 50);  

		
		}
}
