package com.catavolt.satellite.provider.ozinga.login;

import java.io.UnsupportedEncodingException;

public class HexStringConverter {

    //****************************************************************************
    // FIELDS
    //****************************************************************************

    // Constants
    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    // Static fields
    private static HexStringConverter fInstance = new HexStringConverter();

    //****************************************************************************
    // CONSTRUCTORE
    //****************************************************************************

    private HexStringConverter() {
    }

    //****************************************************************************
    // CLASS METHODS
    //****************************************************************************

    public static final HexStringConverter getInstance() {
        return fInstance;
    }

    public static void main(String[] args) {
        try {
            HexStringConverter wConverter = HexStringConverter.getInstance();
            String wHex = wConverter.toHex("catavolt:::catavolt");
            System.out.println("Hex: " + wHex);
            System.out.println("String: " + wConverter.toString(wHex));
        } catch (UnsupportedEncodingException wExc) {
            System.out.println(wExc.getMessage());
            wExc.printStackTrace();
        }
    }

    //****************************************************************************
    // INSTANCE METHODS
    //****************************************************************************

    public String toHex(String pString)
            throws UnsupportedEncodingException
    {
        if (pString == null) {
            return null;
        }
        return asHex(pString.getBytes());
    }

    public String toString(String pHexString) {
        byte[] wAnswer = new byte [pHexString.length() / 2];
        int j=0;
        for (int i=0; i < pHexString.length(); i += 2) {
            wAnswer[j++] = Byte.parseByte(pHexString.substring(i, i + 2), 16);
        }
        return new String(wAnswer);
    }

    private String asHex(byte[] pBytes) {
        char[] wCharArray = new char[2 * pBytes.length];
        for (int i=0; i < pBytes.length; i++) {
            wCharArray[2*i] = HEX_CHARS[(pBytes[i] & 0xF0) >>> 4];
            wCharArray[2*i+1] = HEX_CHARS[pBytes[i] & 0x0F];
        }
        return new String(wCharArray);
    }
}