package cc.kkon;


import cc.kkon.util.PdfSigner;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class PdfSignerTests {

    final String CERT_PWD = "12345678";

    @Test
    public void testSignRSA() throws Exception {
        // prepare parameters
        InputStream pdfIn = getResource("example.pdf");
        OutputStream pdfOut = new FileOutputStream(new File("target/example.sign.rsa.pdf"));
        InputStream p12 = getResource("rsa.p12");
        byte[] sealBytes = IOUtils.toByteArray(getResource("rikka.png"));
        String reason = "TEST";
        String location = "AnHui HeFei";
        String hashAlgorithm = DigestAlgorithms.SHA1;

        // do sign
        PdfSigner.sign(pdfIn, pdfOut, p12, CERT_PWD, sealBytes, reason, location, hashAlgorithm);
    }

    @Test
    public void testSignSM2() throws Exception {
        // prepare parameters
        InputStream pdfIn = getResource("example.pdf");
        OutputStream pdfOut = new FileOutputStream(new File("target/example.sign.sm2.pdf"));
        InputStream p12 = getResource("sm2.p12");
        byte[] sealBytes = IOUtils.toByteArray(getResource("rikka.png"));
        String reason = "TEST";
        String location = "AnHui HeFei";
        String hashAlgorithm = DigestAlgorithms.SM3;

        // do sign
        PdfSigner.sign(pdfIn, pdfOut, p12, CERT_PWD, sealBytes, reason, location, hashAlgorithm);
    }

    private InputStream getResource(String name) {
        return getClass().getClassLoader().getResourceAsStream(name);
    }
}
