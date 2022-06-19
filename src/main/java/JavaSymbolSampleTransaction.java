import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.time.Instant;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;

import static java.lang.System.arraycopy;

public class JavaSymbolSampleTransaction {
    public static void main(String[] args) throws DecoderException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ParseException {
        Security.addProvider(new BouncyCastleProvider());

        // アカウント作成
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        SecureRandom RANDOM = new SecureRandom();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        System.out.println(toHex(privateKey.getEncoded()));
        System.out.println(toHex(publicKey.getEncoded()));

        // アカウント復元
        Ed25519PrivateKeyParameters alicePrivateKey = new Ed25519PrivateKeyParameters(getBytes("BBD394D0EE4E10650D5BF15D1389580C6A6C044481E52022A98CD288A2EB679D"), 0);
        Ed25519PublicKeyParameters alicePublicKey = alicePrivateKey.generatePublicKey();
        System.out.println(toHex(alicePrivateKey.getEncoded()));
        System.out.println(toHex(alicePublicKey.getEncoded()));

        final MessageDigest sha3256Digest = MessageDigest.getInstance("SHA3-256", "BC");
        sha3256Digest.update(alicePublicKey.getEncoded());
        final byte[] publicKeyHash = sha3256Digest.digest();
        final MessageDigest ripemd160Digest = MessageDigest.getInstance("RIPEMD160", "BC");
        ripemd160Digest.update(publicKeyHash);
        final byte[] addressBody = ripemd160Digest.digest();
        byte[] decodedAddress = new byte[24];
        decodedAddress[0] = (byte) 152;
        arraycopy(addressBody, 0, decodedAddress, 1, 20);
        byte[] hash = new byte[20 + 1];
        arraycopy(decodedAddress, 0, hash, 0, 20 + 1);
        System.out.println(toHex(hash));
        sha3256Digest.update(hash);
        byte[] resultHash = sha3256Digest.digest();
        arraycopy(resultHash, 0, decodedAddress, 20 + 1, 3);
        byte[] padded = new byte[24 + 1];
        arraycopy(decodedAddress, 0, padded, 0, decodedAddress.length);
        final Base32 codec = new Base32();
        final byte[] encodedBytes = codec.encode(padded);
        String address = new String(encodedBytes, StandardCharsets.UTF_8).toUpperCase().substring(0, 39);
        System.out.println(address);

        // トランザクション構築
        final byte[] version = new byte[] { 1 };
        final byte[] networkType = new byte[] { (byte)152 };
        final byte[] transactionType = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short)16724).array();
        final byte[] fee = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(16000).array();
        long secondLater7200 = (Instant.now().getEpochSecond() + 7200 - 1637848847) * 1000;
        final byte[] deadline = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(secondLater7200).array();
        final byte[] recipientAddress = codec.decode("TBS2EI4K66LVQ57HMUFXYAJQGIFUR25Z4GTFZUI");
        final byte[] mosaicCount = new byte[] { 1 };
        final byte[] mosaicId = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(Long.decode("0x3A8416DB2D53B6C8")).array();
        final byte[] mosaicAmount = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(100).array();
        final byte[] message = "Hello Symbol!".getBytes(StandardCharsets.UTF_8);
        final byte[] messageSize = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short)("Hello Symbol!".getBytes(StandardCharsets.UTF_8).length + 1)).array();

        final String verifiableBody = toHex(version)
                + toHex(networkType)
                + toHex(transactionType)
                + toHex(fee)
                + toHex(deadline)
                + toHex(recipientAddress)
                + toHex(messageSize)
                + toHex(mosaicCount)
                + "00" + "00000000"
                + toHex(mosaicId)
                + toHex(mosaicAmount)
                + "00" + toHex(message);

        final String verifiableString = "7fccd304802016bebbcd342a332f91ff1f3bb5e902988b352697be245f48e836"
                + verifiableBody;

        byte[] verifiableBuffer = getBytes(verifiableString);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, alicePrivateKey);
        signer.update(verifiableBuffer, 0, verifiableBuffer.length);
        byte[] signature = signer.generateSignature();

        // トランザクション通知
        final byte[] transactionSize = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(getBytes(verifiableBody).length + 108).array();
        var payloadString = toHex(transactionSize)
                + "00000000"
                + toHex(signature)
                + toHex(alicePublicKey.getEncoded())
                + "00000000"
                + verifiableBody;

        String payload = "{ \"payload\" : \"" + payloadString + "\"}";
        var url = new URL("https://sym-test-02.opening-line.jp:3001/transactions");
        var httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("PUT");
        httpCon.setDoInput(true);
        httpCon.setDoOutput(true);
        httpCon.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        httpCon.connect();
        PrintStream ps = new PrintStream(httpCon.getOutputStream());
        ps.print(payload);
        ps.close();
        httpCon.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(httpCon.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        System.out.println(sb);

        // 確認
        var hashableBuffer = getBytes(
                toHex(signature)
                        + toHex(alicePublicKey.getEncoded())
                        + verifiableString
        );

        sha3256Digest.update(hashableBuffer);
        var transactionHash = sha3256Digest.digest();
        System.out.println("transactionStatus: https://sym-test-02.opening-line.jp:3001/transactionStatus/" + toHex(transactionHash));
        System.out.println("confirmed: https://sym-test-02.opening-line.jp:3001/transactions/confirmed/" + toHex(transactionHash));
        System.out.println("explorer: https://testnet.symbol.fyi/transactions/" +  toHex(transactionHash));
    }

    public static String toHex(final byte[] bytes) {
        final Hex codec = new Hex();
        final byte[] decodedBytes = codec.encode(bytes);
        return new String(decodedBytes, StandardCharsets.UTF_8).toUpperCase();
    }

    private static byte[] getBytes(final String hexString) throws DecoderException {
        final Hex codec = new Hex();
        final String paddedHexString = 0 == hexString.length() % 2 ? hexString : "0" + hexString;
        final byte[] encodedBytes = paddedHexString.getBytes(StandardCharsets.UTF_8);
        return codec.decode(encodedBytes);
    }
}
