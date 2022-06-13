package classicapplet1;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
public class ClassicApplet1 extends Applet
{
    byte arrayStore[] = JCSystem.makeTransientByteArray((short)20, JCSystem.CLEAR_ON_RESET);
    short arrayStorLen = (short)0;
    byte ownerName[] = {'J', 'i', 'r', 'i', ' ', 'P', 'a', 's', 'e', 'k'};
    byte pinMaxTries = (byte)0x03;
    byte pinMaxLen = (byte)0x0D;
    byte tempStore[] = JCSystem.makeTransientByteArray((short)81, JCSystem.CLEAR_ON_RESET);
    byte macArray[] = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
    byte dataArray[] = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_RESET);
    OwnerPIN pin;
    Cipher aes128CBC;
    AESKey keyAES;
    Signature macAES;
    AESKey keyAESMAC;
    

    public boolean select()                                     // zdroj: https://www.oracle.com/java/technologies/java-card/javacard-applet.html
    {
        if(pin.getTriesRemaining() == (byte)0)
            return false;

        return true;
    }
    
    public void deselect()
    {
        pin.reset();
        super.deselect();
    }
        
    public void sendOwnerName(APDU apdu)                            // zdroj: ukázka v průběhu cvičení
    {
        short insLen = apdu.setOutgoing();
        if(insLen > ownerName.length)
        {
            insLen = (short)ownerName.length;
        }
        apdu.setOutgoingLength(insLen);
        apdu.sendBytesLong(ownerName, (short)0, insLen);        
    }
    
    public void receiveData(APDU apdu, byte [] apduBuffer)          // zdroj: ukázka v průběhu cvičení
    {
        short insLen = apdu.setIncomingAndReceive();
        if(insLen < (short)arrayStore.length)
        {
            Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, arrayStore, (short)0, (short)insLen);
            arrayStorLen += (short)insLen;
        }
        else
        {
            ISOException.throwIt((short)(0x6700));
        }        
    }
    
    public void sendData(APDU apdu)                              // zdroj: ukázka v průběhu cvičení
    {
        short insLen = apdu.setOutgoing();
        if(insLen != arrayStorLen)
        {
            ISOException.throwIt((short)(0x6c00+arrayStorLen));
            apdu.setOutgoingLength(insLen);
            apdu.sendBytesLong(arrayStore, (short)0, insLen);
        }
        else
        {
            apdu.setOutgoingLength(insLen);
            apdu.sendBytesLong(arrayStore, (short)0, insLen);                    
        }    
    }
    
    public void encryptData(APDU apdu, byte [] apduBuffer)      // zdroje: dokumentace + https://www.fi.muni.cz/~xsvenda/docs/SC_JavaCardCrypto.pdf, https://www.programcreek.com/java-api-examples/?api=javacard.security.KeyBuilder, https://www.programcreek.com/java-api-examples/?api=javacardx.crypto.Cipher
    {
        short insLen = apdu.setIncomingAndReceive();
        if(insLen % 16 != 0)
            ISOException.throwIt((short)(0x6c00 + CryptoException.ILLEGAL_VALUE));
        if(insLen > 64)
            ISOException.throwIt((short)0x6700);
        aes128CBC.init(keyAES, Cipher.MODE_ENCRYPT);
        macAES.init(keyAESMAC, Signature.MODE_SIGN);
        aes128CBC.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, insLen, tempStore, (short)0);
        short tempLen = insLen;
        macAES.sign(tempStore, (short)0, insLen, tempStore, insLen);
        short tempLenMAC = (short)(tempLen + (short)16);
        macAES.init(keyAESMAC, Signature.MODE_VERIFY);
        tempLenMAC = apdu.setOutgoing();
        apdu.setOutgoingLength(tempLenMAC);
        apdu.sendBytesLong(tempStore, (short)0, tempLenMAC);      
    }
    
    public void decryptData(APDU apdu, byte [] apduBuffer)    // zdroje: dokumentace + https://www.fi.muni.cz/~xsvenda/docs/SC_JavaCardCrypto.pdf, https://www.programcreek.com/java-api-examples/?api=javacard.security.KeyBuilder, https://www.programcreek.com/java-api-examples/?api=javacardx.crypto.Cipher
    {
        short insLen = apdu.setIncomingAndReceive();
        if(insLen % 16 != 0)
            ISOException.throwIt((short)(0x6c00 + CryptoException.ILLEGAL_VALUE));
        if(insLen > 80)
            ISOException.throwIt((short)0x6700);
        aes128CBC.init(keyAES, Cipher.MODE_DECRYPT);
        macAES.init(keyAESMAC, Signature.MODE_VERIFY);
        Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, dataArray, (short)0, (short)(insLen - (short)16));
        Util.arrayCopy(apduBuffer, (short)(insLen - (short)16 + ISO7816.OFFSET_CDATA), macArray, (short)0, (short)16);     
        boolean macOK = macAES.verify(dataArray, (short)0, (short)(insLen - (short)16), macArray, (short)0, (short)16);
        if(!macOK)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        aes128CBC.doFinal(dataArray, (short)0, (short)(insLen - (short)16), tempStore, (short)0);
        short tempLen = apdu.setOutgoing();
        apdu.setOutgoingLength(tempLen);
        apdu.sendBytesLong(tempStore, (short)0, tempLen);
    }
    
    public void doAction(APDU apdu, byte [] apduBuffer, byte ins)
    {
        switch(ins)
        {
            case 0x00:
                sendOwnerName(apdu);
                break;
            case 0x01:
                if(!pin.isValidated())
                    ISOException.throwIt((short)0x6301);
                else
                    receiveData(apdu, apduBuffer);
                break;
            case 0x02:
                if(!pin.isValidated())
                    ISOException.throwIt((short)0x6301);
                else
                    sendData(apdu);
                break;
            case 0x20:
                byte pinLen = (byte)apdu.setIncomingAndReceive();
                checkPin(apduBuffer, ISO7816.OFFSET_CDATA, pinLen);
                break;
            case 0x42:
                encryptData(apdu, apduBuffer);
                break;
            case 0x44:
                decryptData(apdu, apduBuffer);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }    
        
    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new ClassicApplet1(bArray, bOffset, bLength);
    }

    protected ClassicApplet1(byte[] bArray, short bOffset, byte bLength)        // zdroje: dokumentace + https://www.fi.muni.cz/~xsvenda/docs/SC_JavaCardCrypto.pdf, https://www.programcreek.com/java-api-examples/?api=javacard.security.KeyBuilder, https://www.programcreek.com/java-api-examples/?api=javacardx.crypto.Cipher
    {
        pin = new OwnerPIN((byte)pinMaxTries, (byte)pinMaxLen);
        pin.update(bArray, (byte)9, bArray[8]);
        aes128CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        keyAES = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        byte keyAEStemp[] = {0x4D, 0x62, 0x51, 0x65, 0x54, 0x68, 0x57, 0x6D, 0x5A, 0x71, 0x34, 0x74, 0x37, 0x77, 0x21, 0x7A};
        keyAES.setKey(keyAEStemp, (short)0);
        macAES = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        keyAESMAC = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128 , false);
        byte keyAESMACtemp[] = {0x6E, 0x5A, 0x72, 0x34, 0x75, 0x37, 0x78, 0x21, 0x41, 0x25, 0x44, 0x2A, 0x47, 0x2D, 0x4B, 0x61};
        keyAESMAC.setKey(keyAESMACtemp, (short)0);  
        register();   
    }
    
    protected void checkPin(byte[] bArray, short bOffset, byte bLength)         // zdroje: dokumentace + https://www.oracle.com/java/technologies/java-card/javacard-applet.html
    {
        if(pin.getTriesRemaining() > (byte)0)
        {
            pin.check(bArray, bOffset, bLength);
        }
        else
        {
            deselect();
        }
    }

    public void process(APDU apdu) 
    {
        byte cla;
        byte ins;
        if(selectingApplet()) ISOException.throwIt(ISO7816.SW_NO_ERROR);
        byte [] apduBuffer = apdu.getBuffer();
        cla = apduBuffer[ISO7816.OFFSET_CLA];
        if(cla != (byte)0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        ins = apduBuffer[ISO7816.OFFSET_INS];
        doAction(apdu, apduBuffer, ins);
    }
}
