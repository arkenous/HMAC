package net.trileg.hmac;

public class Main {

  public static void main(String[] args) {
    byte[] key = {(byte)0xFF, (byte)0xFF};
    byte[] message = {(byte)0xFF, (byte)0xFF, (byte)0xFF};

    HMAC hmac = new HMAC();
    byte[] paddedKey = hmac.paddingKey(key);
    byte[] mac = hmac.genMac(paddedKey, message);
    hmac.outputByteArray("mac: ", mac);
  }
}
