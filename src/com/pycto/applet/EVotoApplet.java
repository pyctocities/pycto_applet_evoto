package com.pycto.applet;

import java.applet.Applet;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.google.gson.Gson;

public class EVotoApplet extends Applet {
	public CSR request_cert = new CSR();

	@Override
	public void start() {
		// TODO Auto-generated method stub
		super.start();
		
		
		setBackground(Color.BLUE);						
		setSize(new Dimension(1024,400));
		
		try {

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
			System.out.println("\nb = " + pseudonimo_cegado);
			//must use modPow() - takes an eternity to compute:
			//b = ((r.pow(e.intValue)).multiply(m)).mod(n);

			//********************* FIRMA (sera la de la CA, ahora es la del mismo usuario, es para ver como se firma) *************************************

			BigInteger pseudonimo_cegado_signado = pseudonimo_cegado.modPow(d,n);
			System.out.println("bs = " + pseudonimo_cegado_signado);

			//********************* DESCEGADO **********************************

			BigInteger pseudonimo_descegado = r.modInverse(n).multiply(pseudonimo_cegado_signado).mod(n);
			System.out.println("s = " + pseudonimo_descegado);

			//********************* VERIFICACIÓN ***********************************

			//LA signatura de M deberia ser = (m^d) mod n
			BigInteger sig_of_m = m.modPow(d,n);
			System.out.println("sig_of_m = " + sig_of_m);

			//Mirar si la signatura es la misma
			System.out.println(pseudonimo_descegado.equals(sig_of_m));

		}
		catch(Exception ex) {
			System.out.println("ERROR: ");
			ex.printStackTrace();
		}
	}
	
	@Override
	public void paint(Graphics g) {
	// TODO Auto-generated method stub
	super.paint(g);
	
	g.setColor(Color.WHITE);
    g.drawString("Esta a punto de votar la imagen", 400, 50);
    
	}


}

