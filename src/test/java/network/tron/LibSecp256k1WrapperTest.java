package network.tron;

import org.bouncycastle.util.encoders.Base64;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class LibSecp256k1WrapperTest {

    @DataProvider(name = "provider")
    private Object[][] loadTestData() throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("test_data.csv");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

        List<Object[]> list = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            final String[] data = line.split(";");
            list.add(new Object[]{Base64.decode(data[0]), data[1]});
        }
        Object[][] ret = new Object[list.size()][];
        return list.toArray(ret);
    }

    @Test(dataProvider = "provider")
    public void testSignatureToAddress(byte[] hash, String sig) throws SignatureException {
        assertEquals(
                LibSecp256k1Wrapper.signatureToAddress(hash, sig),
                org.tron.common.crypto.ECKey.signatureToAddress(hash, sig));
        assertEquals(
                LibSecp256k1Wrapper.signatureToAddress(hash, sig),
                org.tron.common.bccrypto.ECKey.signatureToAddress(hash, sig));
    }
}