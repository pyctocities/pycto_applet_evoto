package com.pycto.applet;

import java.applet.Applet;
import java.awt.Button;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Event;
import java.awt.Graphics;
import java.awt.Label;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import com.google.gson.Gson;

public class EVotoApplet extends Applet {
	public CSR request_cert = new CSR();
	
	public TextField user;
	public TextField pass;
	public TextField id_foto;
    public Button okButton; 
	public Label userlabel = new Label("Usuario: ");
	public Label passlabel = new Label("Password: ");
	public Label idfotolabel = new Label("Id foto: ");

	
	@Override
	public void start() {
		// TODO Auto-generated method stub
		super.start();
		
		setBackground(Color.decode("#6D91B4"));		
		//setSize(new Dimension(1024,400));
		setSize(new Dimension(300,300));
		

		user = new TextField(30);
		pass = new TextField(30);
		id_foto = new TextField(30);
	    okButton = new Button("Votar!"); 

	    
	    userlabel.setBounds(100,85,50,20);
	    user.setBounds(200,70,200,20);
	    user.setVisible(true);
	    
	    passlabel.setBounds(100,135,50,20);
	    pass.setBounds(200,120,200,20);
	    pass.setEchoChar('*');
	    
	    idfotolabel.setBounds(100,185,50,20);
	    id_foto.setBounds(200,170,200,20);
	    
	    okButton.setBounds(200,230,100,20);
	    
	    okButton.addActionListener(l);
	    
	    add(userlabel);
	    add(user);
	    add(passlabel);
	    add(pass);
	    add(idfotolabel);
	    add(id_foto);
	    add(okButton);

	}
	
	@Override
	public void paint(Graphics g) {
	// TODO Auto-generated method stub
		super.paint(g);
		g.setColor(Color.WHITE);
	   // g.drawString("VOTACIÓN DE IMAGEN", 200, 20);
	    

	}
    
    public ActionListener l = new ActionListener() {
		
		@Override
		public void actionPerformed(ActionEvent e) {
					vota();
					JOptionPane.showMessageDialog(null, "Vota hermano!");
				
		}
	};
	
	
	public void vota (){
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



}

