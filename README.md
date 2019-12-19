# aes-encryption
performs aes encryption on an input file

## Instructions
To run the program

```
javac AESEncrypt128.java
java AESEncrypt128 absolutePathToFile
```
where *absolutePathToFile* is the absolute path of the file of plain text.

The program will then prompt you to enter a 32 digit hex value to represent the 128 bit key used for encryption.
On successful encryption, the program will create an output file with the same name as the input file but with the extension of .enc. The output can be found in the same location as the input file and will contain the ciphertext.
