package net.trileg.hmac;

import javax.xml.bind.DatatypeConverter;

public class HMAC {
  private static final int BLOCK_SIZE = 64;
  private byte[] padded_key = new byte[BLOCK_SIZE];
  private byte[] ipad = new byte[BLOCK_SIZE];
  private byte[] opad = new byte[BLOCK_SIZE];

  private SHA1 sha1 = new SHA1();

  public HMAC() {
    for (int i = 0; i < BLOCK_SIZE; i++) {
      ipad[i] = 0b00110110;
      opad[i] = 0b01011100;
    }
  }

  public void outputByteArray(String text, byte[] input) {
    System.out.print(String.format(text + ": len=%d, ", input.length));
    for (byte i : input) {
      System.out.print(String.format("%02x ", i));
    }
    System.out.println();
  }

  public byte[] paddingKey(byte[] key) {
    if (key.length > BLOCK_SIZE) {
      key = DatatypeConverter.parseHexBinary(sha1.getHash(sha1.padding(key)));
      return paddingKey(key);
    } else if (key.length < BLOCK_SIZE) {
      int padSize = BLOCK_SIZE - key.length;
      byte[] zeroBytes = new byte[padSize];
      for (int i = 0; i < padSize; i++) {
        zeroBytes[i] = 0b00000000;
      }
      System.arraycopy(key, 0, padded_key, 0, key.length);
      System.arraycopy(zeroBytes, 0, padded_key, key.length, zeroBytes.length);
    } else {
      padded_key = key;
    }

    return padded_key;
  }

  public byte[] genMac(byte[] key, byte[] message) {
    byte[] ipadkey = new byte[BLOCK_SIZE];
    byte[] opadkey = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
      ipadkey[i] = (byte)(((int)key[i] & 0xff) ^ ((int)ipad[i]) & 0xff);
      opadkey[i] = (byte)(((int)key[i] & 0xff) ^ ((int)opad[i]) & 0xff);
    }

    byte[] ipadkeyMessage = new byte[ipadkey.length + message.length];
    System.arraycopy(ipadkey, 0, ipadkeyMessage, 0, ipadkey.length);
    System.arraycopy(message, 0, ipadkeyMessage, ipadkey.length, message.length);

    sha1 = new SHA1();
    byte[] hashedIpadkeyMessage = DatatypeConverter.parseHexBinary(sha1.getHash(sha1.padding(ipadkeyMessage)));

    byte[] opadkeyMessage = new byte[opadkey.length + hashedIpadkeyMessage.length];
    System.arraycopy(opadkey, 0, opadkeyMessage, 0, opadkey.length);
    System.arraycopy(hashedIpadkeyMessage, 0, opadkeyMessage, opadkey.length, hashedIpadkeyMessage.length);

    sha1 = new SHA1();
    return DatatypeConverter.parseHexBinary(sha1.getHash(sha1.padding(opadkeyMessage)));
  }
}
