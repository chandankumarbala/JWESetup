package com.jwe.encrypt;

public class EncryptionMain {

    public  static void main(String[] args){
      //  EncryptionService service=new EncryptionService();
        //service.encryptTrail();

        System.out.println("---------------------Enc2-------------------------------");

        EncryptionServiceWithPublicKey service2=new EncryptionServiceWithPublicKey();
        service2.encryptTrail();

    }
}
