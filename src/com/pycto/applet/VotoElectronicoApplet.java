package com.pycto.applet;
import java.applet.Applet;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.math.BigInteger;
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
		public PrivateKey priv;
		public PublicKey pub;
	
		@Override
		public void start() {
			// TODO Auto-generated method stub
			super.start();
			
			setBackground(Color.BLUE);						
			setSize(new Dimension(1024,768));
			
			
			
			
			try {
				//Empieza aqui: Generamos a partir de keytool de java las claves publicas y privadas
				
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
				keyGen.initialize(1024, random);
				
				KeyPair pair = keyGen.generateKeyPair();
				priv = pair.getPrivate();
				pub = pair.getPublic();
				
				//Acaba aqui: Generamos a partir de keytool de java las claves publicas y privadas

				//Los guardamos en la clase CSR
				//System.out.println("La clave privada es: "+priv.getEncoded());
				System.out.println("La clave publica es: "+pub);
				System.out.println("La clave publica es: "+pub);

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
				BigInteger csrHashInt = new BigInteger(1, CsrHashed);
				BigInteger m = BigInteger.valueOf(2131414141);
				BigInteger crsHashIntBlinded = csrHashInt.mod(m);
				System.out.println("El CSR: "+csrHashInt);

				System.out.println("El CSR blinder: "+crsHashIntBlinded);

				
				
				
				System.out.println("CSR: "+csrHashInt);
				//BigInteger modulus = pub.getAlgorithm().

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
		
		g.setColor(Color.WHITE);
        g.drawString("Esta a punto de votar la imagen", 400, 50);
        
        g.drawString(pub.toString(), 50, 80);

       
//		g.drawBytes(request_cert.pubKey, 0, request_cert.pubKey.length, 10, 30);
//	    g.drawString (request_cert.pubKey.toString(), 20, 50);  

		
		}
}
