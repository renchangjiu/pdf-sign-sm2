package cc.kkon.util;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class PdfSigner {

    /**
     * 为 pdf 文件签章
     *
     * @param pdfIn         需要签章的pdf
     * @param pdfOut        签完章的pdf
     * @param p12In         p12
     * @param p12Pwd        p12 密码
     * @param sealBytes     印章图片
     * @param reason        签名的原因, 显示在pdf签名属性中, 随便填
     * @param location      签名的地点, 显示在pdf签名属性中, 随便填
     * @param hashAlgorithm hash 算法
     */
    public static void sign(InputStream pdfIn,
                            OutputStream pdfOut,
                            InputStream p12In,
                            String p12Pwd,
                            byte[] sealBytes,
                            String reason,
                            String location,
                            String hashAlgorithm)
            throws GeneralSecurityException, IOException, DocumentException {
        //读取keystore , 获得私钥和证书链
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(p12In, p12Pwd.toCharArray());
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, p12Pwd.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        PdfReader reader = new PdfReader(pdfIn);

        //创建签章工具PdfStamper, 最后一个boolean参数
        //false, pdf文件只允许被签名一次, 多次签名, 最后一次有效
        //true, pdf可以被追加签名, 验签工具可以识别出每次签名之后文档是否被修改
        PdfStamper stamper = PdfStamper.createSignature(reader, pdfOut, '\0', null, true);
        // 获取数字签章属性对象, 设定数字签章的属性
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        //设置签名的位置, 页码, 签名域名称, 多次追加签名的时候, 签名预名称不能一样
        //签名的位置, 是图章相对于pdf页面的位置坐标, 原点为pdf页面左下角
        //四个参数的分别是, 图章左下角x, 图章左下角y, 图章右上角x, 图章右上角y
        Rectangle ps = reader.getPageSize(1);
        int len = 200;
        float x = ps.getWidth() - len;
        appearance.setVisibleSignature(new Rectangle(x, 0, ps.getWidth(), len), 1, "sig1");
        // appearance.setVisibleSignature("sig1");

        //读取图章图片, 这个image是itext包的image
        Image image = Image.getInstance(sealBytes);
        appearance.setSignatureGraphic(image);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        //设置图章的显示方式, 如下选择的是只显示图章（还有其他的模式, 可以图章和签名描述一同显示）
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        // 这里的itext提供了2个用于签名的接口, 可以自己实现, 后边着重说这个实现
        // 摘要算法
        ExternalDigest digest = new BouncyCastleDigest();
        // 签名算法
        ExternalSignature signature = new PrivateKeySignature(pk, hashAlgorithm, null);
        // 调用itext签名方法完成pdf签章CryptoStandard.CMS 签名方式, 建议采用这种
        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

}
