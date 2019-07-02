public class FEALNX {

	public static void main(String[] args) {
		testMethod();
	}
	
	public static String byteArrayToHexString(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for(byte aa : b) {
			sb.append(String.format("%02X", aa));
		}
		String ret = sb.toString();
		sb.setLength(0);
		return ret;
	}
	
	public static String byteToBinaryString(byte b) {
	    StringBuilder sb = new StringBuilder();
	    for (int i = 7; i >= 0; --i) {
	        sb.append(b >>> i & 1);
	    }
		String ret = sb.toString();
		sb.setLength(0);
	    return ret;
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] ret = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        ret[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
									+ Character.digit(s.charAt(i+1), 16));
	    }
	    return ret;
	}
	
	public static byte hexStringToByte(String s) {
		if(s.length() != 2) {
			throw new IllegalArgumentException();
		}
		byte ret = (byte) Character.digit(s.charAt(0), 16);
		ret = (byte) (ret << 4);
		ret = (byte) ((byte) ret + Character.digit(s.charAt(1), 16));
	    return ret;
	}
	
	public static byte[] EncryptFEALNX(byte[] PlainText, byte[] Key, int numberOfRounds) {
		if(PlainText.length == 8 && Key.length == 16 && numberOfRounds >= 0) {
			byte[][] subKeys = KeyGeneration(Key, numberOfRounds);
			byte[] FirstXOR = {subKeys[numberOfRounds][0],
							   subKeys[numberOfRounds][1],
							   subKeys[numberOfRounds+1][0],
							   subKeys[numberOfRounds+1][1],
							   subKeys[numberOfRounds+2][0],
							   subKeys[numberOfRounds+2][1],
							   subKeys[numberOfRounds+3][0],
							   subKeys[numberOfRounds+3][1]};
			PlainText = XORByteArrays(PlainText, FirstXOR);
			byte[] LCurrent = new byte[4];
			System.arraycopy(PlainText, 0, LCurrent, 0, 4);
			byte[] RCurrent = new byte[4];
			System.arraycopy(PlainText, 4, RCurrent, 0, 4);
			RCurrent = XORByteArrays(LCurrent, RCurrent);
			//Core Loop
			for(int i = 0; i < numberOfRounds; i++) {
				LCurrent = XORByteArrays(LCurrent, F(RCurrent,subKeys[i]));
				byte[] SwitchTemp = new byte[4];
				System.arraycopy(LCurrent, 0, SwitchTemp, 0, 4);
				System.arraycopy(RCurrent, 0, LCurrent, 0, 4);
				System.arraycopy(SwitchTemp, 0, RCurrent, 0, 4);
			}
			
			byte[] CipherText = new byte[8];
			byte[] LastXOR = {subKeys[numberOfRounds+4][0],
							  subKeys[numberOfRounds+4][1],
							  subKeys[numberOfRounds+5][0],
							  subKeys[numberOfRounds+5][1],
							  subKeys[numberOfRounds+6][0],
							  subKeys[numberOfRounds+6][1],
							  subKeys[numberOfRounds+7][0],
							  subKeys[numberOfRounds+7][1]};
			LCurrent = XORByteArrays(LCurrent, RCurrent); //TODO This was not included in the specification, but it produces the correct output. 
			System.arraycopy(RCurrent, 0, CipherText, 0, 4);
			System.arraycopy(LCurrent, 0, CipherText, 4, 4);
			CipherText = XORByteArrays(CipherText, LastXOR);
			return CipherText;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte[] DecryptFEALNX(byte[] CipherText, byte[] Key, int numberOfRounds) {
		if(CipherText.length == 8 && Key.length == 16 && numberOfRounds >= 0) {
			//Initialization
			byte[][] subKeys = KeyGeneration(Key, numberOfRounds);
			byte[] FirstXOR = {subKeys[numberOfRounds+4][0],
							   subKeys[numberOfRounds+4][1],
							   subKeys[numberOfRounds+5][0],
							   subKeys[numberOfRounds+5][1],
							   subKeys[numberOfRounds+6][0],
							   subKeys[numberOfRounds+6][1],
							   subKeys[numberOfRounds+7][0],
							   subKeys[numberOfRounds+7][1]};
			CipherText = XORByteArrays(CipherText, FirstXOR);
			byte[] LCurrent = new byte[4];
			System.arraycopy(CipherText, 4, LCurrent, 0, 4);
			byte[] RCurrent = new byte[4];
			System.arraycopy(CipherText, 0, RCurrent, 0, 4);
			LCurrent = XORByteArrays(LCurrent, RCurrent);
			
			//Core Loop
			for(int i = numberOfRounds-1; i >= 0; i--) {
				byte[] SwitchTemp = new byte[4];
				System.arraycopy(LCurrent, 0, SwitchTemp, 0, 4);
				System.arraycopy(RCurrent, 0, LCurrent, 0, 4);
				System.arraycopy(SwitchTemp, 0, RCurrent, 0, 4);
				LCurrent = XORByteArrays(LCurrent, F(RCurrent,subKeys[i]));
			}
			
			byte[] PlainText = new byte[8];
			byte[] LastXOR = {subKeys[numberOfRounds][0],
							  subKeys[numberOfRounds][1],
							  subKeys[numberOfRounds+1][0],
							  subKeys[numberOfRounds+1][1],
							  subKeys[numberOfRounds+2][0],
							  subKeys[numberOfRounds+2][1],
							  subKeys[numberOfRounds+3][0],
							  subKeys[numberOfRounds+3][1]};
			RCurrent = XORByteArrays(LCurrent, RCurrent);
			System.arraycopy(LCurrent, 0, PlainText, 0, 4);
			System.arraycopy(RCurrent, 0, PlainText, 4, 4);
			PlainText = XORByteArrays(PlainText, LastXOR);
			return PlainText;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte[][] KeyGeneration(byte[] userKey, int numberOfRounds) {
		if(userKey.length == 16) {
			//Initialization
			byte[][] subKeys = new byte[numberOfRounds+8][2];
			byte[] ACurrent = new byte[4];
			System.arraycopy(userKey, 0, ACurrent, 0, 4);
			byte[] BCurrent = new byte[4];
			System.arraycopy(userKey, 4, BCurrent, 0, 4);
			byte[] XORTemp = new byte[4];
			byte[] XORResult = new byte[4];
			byte[] KR1 = new byte[4];
			System.arraycopy(userKey, 8, KR1, 0, 4);
			byte[] KR2 = new byte[4];
			System.arraycopy(userKey, 12, KR2, 0, 4);
			byte[] KRX = XORByteArrays(KR1,KR2);
			
			//Core Loop
			for(int i = 0; i < 4 + (numberOfRounds/2); i++) {
				
				if(i%3==0) {
					XORResult = XORByteArrays(BCurrent, KRX);
				} else if(i%3==1) {
					XORResult = XORByteArrays(BCurrent, KR1);
				} else {
					XORResult = XORByteArrays(BCurrent, KR2);
				}
				
				if(i>0) {
					XORResult = XORByteArrays(XORResult, XORTemp);
				}
				
				System.arraycopy(ACurrent, 0, XORTemp, 0, 4); //Saving Carryover
				
				ACurrent = Fktest(ACurrent, XORResult);
				System.arraycopy(ACurrent, 0, subKeys[2*i], 0, 2);
				System.arraycopy(ACurrent, 2, subKeys[(2*i)+1], 0, 2);
				
				byte[] SwitchTemp = new byte[4];
				System.arraycopy(ACurrent, 0, SwitchTemp, 0, 4);
				System.arraycopy(BCurrent, 0, ACurrent, 0, 4);
				System.arraycopy(SwitchTemp, 0, BCurrent, 0, 4);
			}
			
			return subKeys;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static void testMethod() {
		byte[] PT = hexStringToByteArray("0000000100020003");
		byte[] K = hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
		
		//Print Key
		System.out.println("KEY = " + byteArrayToHexString(K));
		
		for(int i = 0; i < 10; i++) {
			for(int j = 0; j < 4096; j++) {
				//Calculate CT
				byte[] CT = EncryptFEALNX(PT, K, 32);
				
				//Print line
				System.out.println("PT: " + byteArrayToHexString(PT) + ",  CT: " + byteArrayToHexString(CT));
				
				//Increment PT
				for(int k = 0; k < PT.length; k++) {
					if(k % 2 == 0) {
						if(PT[k+1] == hexStringToByte("FF")) {
							PT[k]++;
						}
					} else {
						if(PT[k] == hexStringToByte("FF")) {
							PT[k] = hexStringToByte("00");
						} else {
							PT[k]++;
						}
					}
				}
			}
			//Stop after end of 10th round
			if(i == 9) break;
			
			//Shift key left by 1, append next highest byte
			for(int j = 0; j < K.length - 1; j++) {
				K[j] = K[j+1];
			}
			K[K.length-1] = (byte) (K[K.length-2] + 1);
			
			//Reset PT
			PT = hexStringToByteArray("0000000100020003");
			
			//Print spacer
			System.out.println();
			
			//Print key
			System.out.println("KEY = " + byteArrayToHexString(K));
		}
	}
	
	public static byte[] Fk(byte[] a, byte[] b) {																					
		if(a.length == 4 && 4 == b.length) {
			byte r2 = S((byte)(a[0]^a[1]), (byte)(b[0]^((byte)a[2]^a[3])), (byte) 1);
			byte r1 = S(a[0], (byte)(b[2]^r2), (byte) 0);
			byte r3 = S((byte)(a[2]^a[3]), (byte)(b[1]^S((byte)(a[0]^a[1]),(byte)(b[0]^((byte)(a[2]^a[3]))),(byte)1)), (byte)0);
			byte r4 = S(a[3], (byte)(b[3]^r3), (byte)1);
			byte[] ret = {r1,r2,r3,r4};
			return ret;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte[] Fktest(byte[]a, byte[]b) {
		byte fk1 = (byte) ((byte) a[0]^a[1]);
		byte fk2 = (byte) ((byte) a[2]^a[3]);
		fk1 = functionS(fk1, (byte) (fk2^b[0]),(byte)1);
		fk2 = functionS(fk2, (byte) (fk1^b[1]),(byte)0);
		byte fk0 = functionS(a[0], (byte) (fk1^b[2]), (byte)0);
		byte fk3 = functionS(a[3], (byte) (fk2^b[3]), (byte)1);
		byte[] ebat = {fk0, fk1, fk2, fk3};
		return ebat;
	}
	
	public static byte[] F(byte[] a, byte[] b) {
		if(a.length == 4 && b.length == 2) {
			byte t1 = (byte)(a[3]^a[2]^b[1]);
			byte r2 = S((byte)(a[0]^a[1]^b[0]),t1,(byte)1);
			byte r1 = S(a[0],r2,(byte)0);
			byte r3 = S(t1,r2,(byte)0);
			byte r4 = S(r3,a[3],(byte)1);
			byte[] ret = {r1,r2,r3,r4};
			return ret;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte S(byte A, byte B, byte D) {
		if(D == 0 || D == 1) {
			byte T = (byte) ((A+B+D%256));
			return rotateLeft(T,2);
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte rotateLeft(byte bits, int shift) {
	    return (byte)(((bits & 0xff) << shift) | ((bits & 0xff) >>> (8 - shift)));
	}
	
	public static byte functionS(byte A, byte B, byte delta) {
		byte T = (byte)(((A&255) + (B&255) + (delta&255))%256);
		return (byte)(((T&255)<<(byte)2)|((T&255)>>>(byte)6));
	}
	
	public static byte[] XORByteArrays(byte[] a, byte[] b) {
		if(a.length == b.length) {
			byte[] ret = new byte[a.length];
			for(int i = 0; i < a.length; i++) {
				ret[i] = (byte) ((byte) a[i]^b[i]);
			}
			return ret;
		} else {
			throw new IllegalArgumentException();
		}
	}
}
