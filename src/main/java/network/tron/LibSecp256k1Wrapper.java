package network.tron;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.util.encoders.Base64;
import org.tron.common.crypto.Hash;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;

public class LibSecp256k1Wrapper {
    public static byte[] signatureToAddress(byte[] hash, String signature) throws SignatureException {
        final byte[] sigDecoded = Base64.decode(signature);
        final ECKey.ECDSASignature sig = new ECKey.ECDSASignature(
                new BigInteger(1, Arrays.copyOfRange(sigDecoded, 1, 33)),
                new BigInteger(1, Arrays.copyOfRange(sigDecoded, 33, 65))
        );
        byte header = (byte) (sigDecoded[0] & 0xFF);
        if (header < 27 || header > 34) {
            throw new SignatureException("Header byte out of range: " + header);
        } else if (header >= 31) {
            header -= 4;
        }
        final int recId = header - 27;
        final ECKey key = ECKey.recoverFromSignature(recId, sig, Sha256Hash.wrap(hash), false);
        final byte[] pubBytes = key.getPubKey();
        return Hash.sha3omit12(Arrays.copyOfRange(pubBytes, 1, pubBytes.length));
    }
}
