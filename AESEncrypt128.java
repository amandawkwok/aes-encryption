import java.io.*;

public class AESEncrypt128 {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("No file specified. Try again.");
        } else if (args.length > 1) {
            System.out.println("The file name should be the only command line "
                    + "argument. Please try again.");
        } else {
            try {
                String filePath = args[0];
                File file = new File(filePath);

                if (!file.isAbsolute()) {
                    throw new Exception("e");
                }

                DataInputStream in = new DataInputStream(new FileInputStream(file));

                // Prompt user for key
                Console console = System.console();
                System.out.print("Please enter a 32 digit hex key: ");
                char[] key = console.readPassword();

                while (key.length != 32 || !isHexString(key)) {
                    System.out.print("Error! The key is not a 32 digit hex value. Please "
                            + "try again: ");
                    key = console.readPassword();
                }
 
                // Retrieve keys from key scheduler
                char[][] keySchedule = getKeySchedule(key);

                // Open output file for the ciphertext
                String outputFilePath = filePath.substring(0, filePath.lastIndexOf(".")) + ".enc";
                DataOutputStream out = new DataOutputStream(new FileOutputStream(outputFilePath, false));

                // Acquire 16 bytes for each AES encryption
                byte[] fBuffer = new byte[16];
                int bytesRead;
                
                while ((bytesRead = in.read(fBuffer)) != -1) {
                    if (bytesRead < 16) {
                        for (int i = bytesRead; i < 16; i++) {
                            fBuffer[i] = 0x00;
                        }
                    }
                    
                    addKey(fBuffer, keySchedule[0]);

                    for (int i = 1; i <= 9; i++) {
                        subBytes(fBuffer);
                        shiftRows(fBuffer);
                        fBuffer = mixColumns(fBuffer);
                        addKey(fBuffer, keySchedule[i]);
                    }

                    subBytes(fBuffer);
                    shiftRows(fBuffer);
                    addKey(fBuffer, keySchedule[10]);

                    out.write(fBuffer);

                    fBuffer = new byte[16];
                }
                
                System.out.println("Success! The ciphertext can be found in " + outputFilePath);
                
                in.close();
                out.close();
            }
            catch (Exception e) {
                System.out.println("Error! Please verify that the command line argument is an absolute path " +
                        "to a valid file.");
            }
        }   
    }

    private static void addKey(byte[] state, char[] key) {
        for (int i = 0; i < state.length; i++) {
            state[i] = (byte) (state[i] ^ key[i]);
        }
    }

    private static char[] coreFunction(char[] wordBlock, int iteration) {
        char[] hexDigits;
        int column, row;

        // Shift left
        char firstValue = wordBlock[0];
        for (int k = 0; k < wordBlock.length - 1; k++) {
            wordBlock[k] = wordBlock[k + 1];
        }
        wordBlock[wordBlock.length - 1] = firstValue;

        // S-box lookup
        for (int i = 0; i < wordBlock.length; i++) {
            hexDigits = String.format("%02X", (int) wordBlock[i]).toCharArray();

            row = Integer.parseInt(Character.toString(hexDigits[0]), 16);
            column = Integer.parseInt(Character.toString(hexDigits[1]), 16);
            wordBlock[i] = S_BOX[row * 16 + column];

            if (i == 0) {
                wordBlock[0] ^= R_CON[iteration];
            }
        }

        return wordBlock;
    }

    /**
     * Performs multiplication in a finite field using Galois fields
     * @param a the first multiplicand in binary
     * @param b the second multiplicand in binary
     * @return the product of a and b
     */
    private static int galoisMultiply (int a, int b) {
        int p = 0;
        boolean carry;
        for (int i = 0; i < 8; i++) {

            // 1. If the rightmost bit of b is set, exclusive OR p with a
            if ((b & 1) > 0)
                p ^= a;

            // 2. Shift b one bit to the right, and make the leftmost bit 0
            b = (b >> 1);
            b = (b & 0x7F);

            // 3. Let carry track whether the leftmost bit of a is 1
            carry = ((a & 0x80) == 0x80);

            // 4. Shift a one bit to the left, and make the rightmost bit 0
            a = (a << 1) ;
            a &= 0xFE;

            // 5. If carry is true, exclusive or 1 with 0x1b
            if (carry) {
                a ^= 0x1b;
            }
        }
        return p;
    }

    private static char[][] getKeySchedule(char[] key) {

        char[] firstKey = new char[16];

        for (int i = 0 ; i < key.length; i += 2) {
            Integer firstDigit = Character.getNumericValue(key[i]) << 4;
            Integer secondDigit = Character.getNumericValue(key[i+1]);

            int hexByte = firstDigit | secondDigit;

            firstKey[i/2] = (char)hexByte;
        }

        char[][] keySchedule = new char[11][16];
        keySchedule[0] = firstKey;

        for (int m = 1; m <= 10; m++) {

            char[] wordBlock = {keySchedule[m-1][12],
                    keySchedule[m-1][13], keySchedule[m-1][14], keySchedule[m-1][15]};
            char[] coreResult = coreFunction(wordBlock, m);

            for (int i = 0; i < 4; i++) {
                keySchedule[m][i] = (char)(keySchedule[m-1][i] ^ coreResult[i]);
            }

            for (int i = 4; i < 16; i++) {
                keySchedule[m][i] = (char)(keySchedule[m-1][i] ^ keySchedule[m][i-4]);
            }
        }
        return keySchedule;
    }

    private static boolean isHexString(char[] input) {
        for (char digit : input) {
            if (!((digit >= 'A' && digit <= 'F') || (digit >= 'a' && digit <= 'f') || (digit >= '0' && digit <= '9'))) {
                return false;
            }
        }
        return true;
    }

    private static byte[] mixColumns(byte[] state) {
        byte[] product = new byte[16];

        for (int i = 0; i < state.length; i++) {
            product[i] = 0;
            for (int j = 0, k = i % 4 ; j < 4; j++) {
                product[i] ^= galoisMultiply(MIX_COLUMN[k * 4 + j], state[(i/4) * 4 + j]);
            }
        }

        return product;
    }

    private static void shiftRows(byte[] state) {
        byte firstValue;
        int prevIndex, currIndex;

        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < i; j++) {
                firstValue = state[i];

                for (int k = 1; k < 4; k++) {
                    prevIndex = (i+4*(k-1));
                    currIndex = (i+4*k);

                    state[prevIndex] = state[currIndex];
                }
                state[i+12] = firstValue;
            }
        }
    }

    private static void subBytes(byte[] state) {
        char[] hexDigits;
        int row, column;

        for (int i = 0; i < state.length; i++) {
            hexDigits = String.format("%02X", state[i]).toCharArray();

            row = Integer.parseInt(Character.toString(hexDigits[0]), 16);
            column = Integer.parseInt(Character.toString(hexDigits[1]), 16);

            state[i] = (byte)S_BOX[row * 16 + column];
        }
    }

    private static final char[] MIX_COLUMN = 
        {0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02};

    private static final char[] R_CON = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    
    private static final char[] S_BOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
}