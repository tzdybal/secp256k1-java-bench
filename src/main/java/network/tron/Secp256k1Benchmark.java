package network.tron;

import lombok.AllArgsConstructor;
import org.bouncycastle.util.encoders.Base64;
import org.openjdk.jmh.annotations.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
public class Secp256k1Benchmark {
    @AllArgsConstructor
    private class TestCase {
        byte[] hash;
        String sig;
    }

    private List<TestCase> testCases;

    @Setup
    public void prepare() throws IOException {
        testCases = loadTestData();
    }

    private List<TestCase> loadTestData() throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("test_data.csv");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

        List<TestCase> list = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            final String[] data = line.split(";");
            list.add(new TestCase(Base64.decode(data[0]), data[1]));
        }
        return list;
    }

    private void doTest() {
        testCases.forEach(testCase -> {

        });
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @OperationsPerInvocation(100)
    public void spongyCastleSigToAddr() throws SignatureException {
        for (TestCase testCase : testCases) {
            org.tron.common.crypto.ECKey.signatureToAddress(testCase.hash, testCase.sig);
        }
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @OperationsPerInvocation(100)
    public void bouncyCastleSigToAddr() throws SignatureException {
        for (TestCase testCase : testCases) {
            org.tron.common.bccrypto.ECKey.signatureToAddress(testCase.hash, testCase.sig);
        }
    }

//    @Benchmark
//    @OutputTimeUnit(TimeUnit.MILLISECONDS)
//    @OperationsPerInvocation(100)
//    public void libsecp256k1KeyRecovery() {
//
//    }

}
