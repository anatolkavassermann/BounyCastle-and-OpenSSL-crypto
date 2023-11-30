using iText.Signatures;
using iText.Kernel.Pdf;
using iText.Kernel.Geom;
using iText.Layout;
using iText.Kernel.Pdf.Canvas;
using iText.Kernel.Pdf.Canvas.Parser;
using iText.Kernel.Pdf.Canvas.Parser.Listener;
using iText.Kernel.Pdf.Xobject;
using iText.Kernel.Font;
using iText.Layout.Element;
using iText.Layout.Borders;
using iText.Kernel.Colors;
using iText.Layout.Properties;
using iText.IO.Image;

using System.Text;
using System.Collections;
using System.Xml;

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Ocsp;

var ToBeSigned = "Hello, world!";
var ToBeSignedFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\toBeSigned.txt";
File.WriteAllBytes(ToBeSignedFileName, Encoding.ASCII.GetBytes(ToBeSigned));

var PDFToBeSignedFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\tbs.pdf";

//keydata
var PrKeyFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\prk.pem";
var PbKeyFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\pbk.pem";

//Rawsig FileName
var RawSigFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\toBeSignedRaw.sig";

//For CA
var CertRequestFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\req.req";
var CertRequestWithCustomDirectoryStringAttributesFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\req_custom.req";
var SelfSignedCertFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\cert.crt";
var IssuedCertFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\issued_cert.crt";
var CRLFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\crl.crl";
var OCSPResponseFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\ocsp.resp";
var OCSPRequestFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\ocsp.req";
var OCSPCertToBeVerified = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\userOCSP.cer";
var RootCertFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\root.cer";

//For PFX
var PFXFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\pfx.pfx";
var PFXPass = "12345qwerty";

//For CAdES, XMLDSIG and PAdES
var CAdESBES_SigFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\toBeSigned_CAdESBES.sig";
var XMLDSIG_SigFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\XMLtoBeSigned_XMLDSIG.signed.xml";
var PAdES_SigFileName = "C:\\Users\\user\\Desktop\\MyPrograms\\Experiments\\hack_cont_new\\data\\PDFtoBeSigned_PAdES.signed.pdf";


Console.WriteLine("Begin tests (v. 1.2)\nAuthor: TolikTipaTut1\n-------------------------------------------");

//tests
Sample_1_GenerateGost34102012KeyPair(PrKeyFileName, PbKeyFileName, ToBeSignedFileName);
Sample_2_ReadGost34102012KeyPairFromFile(PrKeyFileName, PbKeyFileName, ToBeSignedFileName);
Sample_3_SignAndExportRawSignatureToFile(PrKeyFileName, PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_4_ImportAndVerifyRawSignature(PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_5_GeneratePKCS10CertRequest(PrKeyFileName, PbKeyFileName, CertRequestFileName);
Sample_6_GeneratePKCS10CertRequestWithCustomDirectoryString(PrKeyFileName, PbKeyFileName, CertRequestWithCustomDirectoryStringAttributesFileName);
Sample_7_GenerateSelfSignedX509Certificate(PrKeyFileName, PbKeyFileName, SelfSignedCertFileName);
Sample_8_ExportPfx(PrKeyFileName, PFXFileName, SelfSignedCertFileName, PFXPass);
Sample_9_ImportPfx(PFXFileName, PFXPass);
Sample_10_SignCertRequest(PFXFileName, PFXPass, CertRequestFileName, IssuedCertFileName);
Sample_11_SignCRL(CRLFileName, PFXFileName, PFXPass);
//Sample_12_CreateOCSPRequest(OCSPCertToBeVerified, RootCertFileName, OCSPRequestFileName);

static void Sample_1_GenerateGost34102012KeyPair(string _PrKeyFileName, string _PbKeyFileName, string _ToBeSignedFileName)
{
    Console.WriteLine("\nSample_1_GenerateGost34102012KeyPair");
    var secureRandom = new SecureRandom();
    var curve = ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-XchA");
    var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
    var ECGost3410Parameters = new ECGost3410Parameters(
        new ECNamedDomainParameters(
            new DerObjectIdentifier("1.2.643.2.2.36.0"),
            domainParameters),
        new DerObjectIdentifier("1.2.643.2.2.36.0"),
        new DerObjectIdentifier("1.2.643.7.1.1.2.2"),
        null
    );
    var ECKeyGenerationParameters = new ECKeyGenerationParameters(ECGost3410Parameters, secureRandom);
    var keyGenerator = new ECKeyPairGenerator();
    keyGenerator.Init(ECKeyGenerationParameters);
    var keyPair = keyGenerator.GenerateKeyPair();
    Console.WriteLine("Key pair generated!");
    Console.WriteLine("Calculating signature...");
    var hashCode = DigestUtilities.CalculateDigest(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, File.ReadAllBytes(_ToBeSignedFileName));
    var signer = new ECGost3410Signer();
    var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)keyPair.Private, secureRandom);
    signer.Init(true, paramsWithRandom);
    Org.BouncyCastle.Math.BigInteger[] signature;
    do
    {
        signature = signer.GenerateSignature(hashCode);
    } while ((signature[0].SignValue != 1) && (signature[1].SignValue != 1));
    Console.WriteLine("Signature calculated!");
    Console.WriteLine("Verifying signature...");
    signer.Init(false, (AsymmetricKeyParameter)keyPair.Public);
    var verificationResult = signer.VerifySignature(hashCode, signature[0], signature[1]);
    Console.WriteLine($"Signature verification result: {verificationResult}");
    switch (verificationResult)
    {
        case bool value when value.Equals(true): {
                WritePemObject(keyPair.Private, _PrKeyFileName);
                WritePemObject(keyPair.Public, _PbKeyFileName);
                Console.WriteLine($"Private key successfully exported to file \"{_PrKeyFileName}\"");
                Console.WriteLine($"Public key successfully exported to file \"{_PbKeyFileName}\"");
                break;
            }
        case bool value when value.Equals(false): {
                Console.WriteLine("Key pair not exported!");
                break;
            }
    }
}

static void Sample_2_ReadGost34102012KeyPairFromFile(string _PrKeyFileName, string _PbKeyFileName, string _ToBeSignedFileName)
{
    Console.WriteLine("\nSample_2_ReadGost34102012KeyPairFromFile");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Calculating signature...");
    var hashCode = DigestUtilities.CalculateDigest(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, File.ReadAllBytes(_ToBeSignedFileName));
    var signer = new ECGost3410Signer();
    var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)prk, secureRandom);
    signer.Init(true, paramsWithRandom);
    Org.BouncyCastle.Math.BigInteger[] signature;
    do
    {
        signature = signer.GenerateSignature(hashCode);
    } while ((signature[0].SignValue != 1) && (signature[1].SignValue != 1));
    Console.WriteLine("Signature calculated!");
    Console.WriteLine("Verifying signature...");
    signer.Init(false, (AsymmetricKeyParameter)pbk);
    bool result = signer.VerifySignature(hashCode, signature[0], signature[1]);
    Console.WriteLine($"Signature verification result: {result}");
    Console.WriteLine($"Key pair match: {result}");
}

static void Sample_3_SignAndExportRawSignatureToFile(string _PrKeyFileName, string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
{
    Console.WriteLine("\nSample_3_SignAndExportRawSignatureToFile");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Calculating signature...");
    var hashCode = DigestUtilities.CalculateDigest(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, File.ReadAllBytes(_ToBeSignedFileName));
    var signer = new ECGost3410Signer();
    var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)prk, secureRandom);
    signer.Init(true, paramsWithRandom);
    Org.BouncyCastle.Math.BigInteger[] signature;
    do
    {
        signature = signer.GenerateSignature(hashCode);
    } while ((signature[0].SignValue != 1) && (signature[1].SignValue != 1));
    Console.WriteLine("Signature calculated!");
    Console.WriteLine("Verifying signature...");
    signer.Init(false, (AsymmetricKeyParameter)pbk);
    bool result = signer.VerifySignature(hashCode, signature[0], signature[1]);
    Console.WriteLine($"Signature verification result: {result}");
    Console.WriteLine($"Key pair match: {result}");
    switch (result)
    {
        case true:
            {
                List<byte> sig = new List<byte>();
                sig.AddRange(signature[0].ToByteArrayUnsigned());
                sig.AddRange(signature[1].ToByteArrayUnsigned());
                File.WriteAllBytes(_RawSigFileName, sig.ToArray());
                Console.WriteLine($"Raw signature successfully exported to file \"{_RawSigFileName}\"");
                break;
            }
        default:
            {
                Console.WriteLine("Raw signature not exported");
                break;
            }
    }
}

static void Sample_4_ImportAndVerifyRawSignature(string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
{
    Console.WriteLine("\nSample_4_ImportAndVerifyRawSignature");
    var hashCode = DigestUtilities.CalculateDigest(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, File.ReadAllBytes(_ToBeSignedFileName));
    byte[] signatureBytes = File.ReadAllBytes(_RawSigFileName);
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Verifying signature...");
    Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(1, signatureBytes.Take(32).ToArray());
    Org.BouncyCastle.Math.BigInteger s = new Org.BouncyCastle.Math.BigInteger(1, signatureBytes.Skip(32).Take(32).ToArray());
    var signer = new ECGost3410Signer();
    signer.Init(false, (AsymmetricKeyParameter)pbk);
    var result = signer.VerifySignature(hashCode, r, s);
    Console.WriteLine($"Signature verification result: {result}");
}

//Этот метод применим во многих случаях, рекомендую юзать именно его
//Но если вдруг потребуется в subjectName/issuerName добавлять какие-то 
//кастомные атрибуты (мол, хочу, значца, в subjectName заиметь ИНН, но чтобы это был не numericString, а UTF8String)
//то следует обратить внимание на sample_6
//если вы не поняли прикола, то смело юзайте sample_5

static void Sample_5_GeneratePKCS10CertRequest(string _PrKeyFileName, string _PbKeyFileName, string _CertRequestFileName)
{
    Console.WriteLine("\nSample_5_GeneratePKCS10CertRequest");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Generating PKCS#10 certification request...");
    X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
    extGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature ^ KeyUsage.NonRepudiation ^ KeyUsage.DataEncipherment));
    extGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
    var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256), pbk.Q.GetEncoded());
    var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);
    extGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));
    AttributePkcs attributePkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
    ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prk);
    var request = new Pkcs10CertificationRequest(
        signatureFactory,
        new X509Name("CN=TolikTipaTut1, L=Москва"),
        (AsymmetricKeyParameter)pbk,
        new DerSet(attributePkcs)
    );
    Console.WriteLine("PKCS#10 certification request generated!");
    Console.WriteLine("Verifying PKCS#10 certification request...");
    var result = request.Verify(pbk);
    Console.WriteLine($"PKCS#10 certification request verification result: {result}");
    switch (result)
    {
        case true:
            {
                WritePemObject(request, _CertRequestFileName);
                Console.WriteLine($"PKCS#10 certification request successfully exported to file \"{_CertRequestFileName}\"");
                break;
            }
    }
}


//Что такое DirectoryString - см. в RFC 5280
static void Sample_6_GeneratePKCS10CertRequestWithCustomDirectoryString(string _PrKeyFileName, string _PbKeyFileName, string _CertRequestFileName)
{
    Console.WriteLine("\nSample_5_GeneratePKCS10CertRequest");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Generating PKCS#10 certification request...");
    X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
    extGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature ^ KeyUsage.NonRepudiation ^ KeyUsage.DataEncipherment));
    extGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
    var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256), pbk.Q.GetEncoded());
    var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);
    extGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));
    AttributePkcs attributePkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
    ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prk);
    Console.WriteLine("Generating custom directory string attributes...");
    var subjectNameOidList = new List<DerObjectIdentifier>();
    subjectNameOidList.Add(X509Name.CN);
    subjectNameOidList.Add(X509Name.L);
    subjectNameOidList.Add(new DerObjectIdentifier("1.2.643.100.3")); //типа добавляем СНИЛС
    subjectNameOidList.Add(X509Name.E);
    var subjectNameAsn1Vector = new Asn1EncodableVector();
    foreach (DerObjectIdentifier oid in subjectNameOidList)
    {
        AttributeTypeAndValue attributeAndTypeValue = null;
        switch (oid)
        {
            case DerObjectIdentifier value when value.Equals(X509Name.CN):
                {
                    attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerUtf8String("TolikTipaTut1 точно тут был"));
                    break;
                }
            case DerObjectIdentifier value when value.Equals(X509Name.L):
                {
                    attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerUtf8String("TolikTipaTut1 точно тут был, можешь не сомнваться!"));
                    break;
                }
            case DerObjectIdentifier value when value.Equals(new DerObjectIdentifier("1.2.643.100.3")):
                {
                    attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerNumericString(Encoding.ASCII.GetBytes("123456780901"))); //добавили СНИЛС
                    break;
                }
            case DerObjectIdentifier value when value.Equals(X509Name.E):
                {
                    var email = Encoding.Unicode.GetString(Encoding.Convert(Encoding.UTF8, Encoding.Unicode, Encoding.UTF8.GetBytes("это извращение, знаю, но на что только не пойдешь@ради экспериментов.com"))); //в RFC 5280 явно сказано, что email должен быть IA5String, но у нас в примере это будет UTF8String. Я просто показываю, как можно настроить, поэтому вот это вот точно 1:1 юзать не стоит XD
                    attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerUtf8String(email));
                    break;
                }
        }
        subjectNameAsn1Vector.Add(new DerSet(attributeAndTypeValue));
    }
    //разворачиваем последовательность атрибутов в subjectName
    Asn1EncodableVector newAsn1EncodableVector = new();
    IEnumerable<Asn1Encodable> listSubjectNameAsn1Vector = subjectNameAsn1Vector.Reverse();
    foreach (Asn1Encodable e in listSubjectNameAsn1Vector)
        newAsn1EncodableVector.Add(e);
    var derSubjectName = new DerSequence(newAsn1EncodableVector);
    X509Name subject = X509Name.GetInstance(derSubjectName.GetDerEncoded());
    //Формируем запрос
    var request = new Pkcs10CertificationRequest(
        signatureFactory,
        subject,
        (AsymmetricKeyParameter)pbk,
        new DerSet(attributePkcs)
    );
    Console.WriteLine("PKCS#10 certification request generated!");
    Console.WriteLine("Verifying PKCS#10 certification request...");
    var result = request.Verify(pbk);
    Console.WriteLine($"PKCS#10 certification request verification result: {result}");
    switch (result)
    {
        case true:
            {
                WritePemObject(request, _CertRequestFileName);
                Console.WriteLine($"PKCS#10 certification request successfully exported to file \"{_CertRequestFileName}\"");
                break;
            }
    }
}

static void Sample_7_GenerateSelfSignedX509Certificate(string _PrKeyFileName, string _PbKeyFileName, string _SelfSignedCertFileName)
{
    Console.WriteLine("\nSample_7_GenerateSelfSignedX509Certificate");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
    Console.WriteLine($"Public key successfully retrieved from file \"{_PbKeyFileName}\"");
    Console.WriteLine("Generating x509 certificate...");
    Console.WriteLine("Generating serial number...");
    Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
    Console.WriteLine($"Certificate serial number: {Convert.ToHexString(serial.ToByteArrayUnsigned())}");
    var certGen = new X509V3CertificateGenerator();
    certGen.SetSerialNumber(serial);
    certGen.SetIssuerDN(new X509Name("CN=TolikTipaTut1"));
    certGen.SetNotBefore(DateTime.UtcNow);
    certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
    certGen.SetPublicKey(pbk);
    certGen.SetSubjectDN(new X509Name("CN=TolikTipaTut1"));
    var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256), pbk.Q.GetEncoded());
    var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);
    certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature ^ KeyUsage.NonRepudiation ^ KeyUsage.DataEncipherment));
    certGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
    certGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));
    ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prk);
    var x509 = certGen.Generate(signatureFactory);
    Console.WriteLine("x509 certificate generated!");
    Console.WriteLine("Verifying generated x509 certificate...");
    bool flag;
    try
    {
        x509.Verify(pbk);
        flag = true;
    }
    catch
    {
        flag = false;
    }
    Console.WriteLine($"Verification result: {flag}");
    switch (flag)
    {
        case true:
            {
                WritePemObject(x509, _SelfSignedCertFileName);
                Console.WriteLine($"Self-signed x509 certificate successfully exported to file \"{_SelfSignedCertFileName}\"");
                break;
            }
        default:
            {
                break;
            }
    }
}

static void Sample_8_ExportPfx(string _PrKeyFileName, string _PFXFileName, string _CertFileName, string _PFXPass)
{
    Console.WriteLine("\nSample_8_ExportPfx");
    var secureRandom = new SecureRandom();
    ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
    Console.WriteLine($"Private key successfully retrieved from file \"{_PrKeyFileName}\"");
    X509Certificate x509 = (X509Certificate)ReadPemObject(_CertFileName);
    Console.WriteLine($"x509 certificate successfully retrieved from file \"{_CertFileName}\"");
    Console.WriteLine("Generating PKCS#12 container...");
    var pkcs12Builder = new Pkcs12StoreBuilder();
    pkcs12Builder.SetUseDerEncoding(true);
    var store = pkcs12Builder.Build();
    store.SetKeyEntry("prk", new AsymmetricKeyEntry((AsymmetricKeyParameter)prk), new X509CertificateEntry[] { new X509CertificateEntry(x509) });
    store.SetCertificateEntry("cert", new X509CertificateEntry(x509));
    var m = new MemoryStream();
    store.Save(m, _PFXPass.ToCharArray(), secureRandom);
    var data = m.ToArray();
    var pkcs12Bytes = Pkcs12Utilities.ConvertToDefiniteLength(data);
    Console.WriteLine("PKCS#12 container successfully generated!");
    File.WriteAllBytes(_PFXFileName, pkcs12Bytes);
    Console.WriteLine($"PKCS#12 container successfully exported to file \"{_PFXFileName}\"!");
}

static void Sample_9_ImportPfx(string _PFXFileName, string _PFXPass)
{
    Console.WriteLine("\nSample_9_ImportPfx");
    var secureRandom = new SecureRandom();
    try
    {
        Console.WriteLine("Retrieving PKCS#12 container...");
        var pfxBytes = File.ReadAllBytes(_PFXFileName);
        Console.WriteLine($"PKCS#12 container successfully retrieved from file \"{_PFXFileName}\"");
        var builder = new Pkcs12StoreBuilder();
        builder.SetUseDerEncoding(true);
        var store = builder.Build();
        var m = new MemoryStream(pfxBytes);
        store.Load(m, _PFXPass.ToCharArray());
        m.Close();
        Console.WriteLine("Retrieving privtate key from PKCS#12 container...");
        var prkBag = store.GetKey("prk");
        Console.WriteLine("Privtate key successfully retrieved from PKCS#12 container!");
        var certBag = store.GetCertificate("cert");
        Console.WriteLine("x509 certificate successfully retrieved from PKCS#12 container!");
        Console.WriteLine("Verifying whether retreived key pair is valid...");
        string testString = "Hello, world!";
        var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), Encoding.ASCII.GetBytes(testString));
        var signer = new ECGost3410Signer();
        var paramsWithRandom = new ParametersWithRandom(prkBag.Key, secureRandom);
        signer.Init(true, paramsWithRandom);
        var signature = signer.GenerateSignature(hashCode);
        signer.Init(false, certBag.Certificate.GetPublicKey());
        var result = signer.VerifySignature(hashCode, signature[0], signature[1]);
        Console.WriteLine($"PFX key pair match: {result}");
    }
    catch
    {
        Console.WriteLine("PKCS#12 container NOT imported!");
    }
}

static void Sample_10_SignCertRequest(string _PFXFileName, string _PFXPass, string _CertRequestFileName, string _IssuedCertFileName)
{
    Console.WriteLine("\nSample_10_SignCertRequest");
    var secureRandom = new SecureRandom();
    Console.WriteLine($"Retrieving PKCS#10 certification request...");
    Pkcs10CertificationRequest reqToBeSigned = (Pkcs10CertificationRequest)ReadPemObject(_CertRequestFileName);
    Console.WriteLine($"PKCS#10 certification request successfully retrieved from file \"{_CertRequestFileName}\"!");
    Console.WriteLine("Verifying PKCS#10 certification requests' proof of possession...");
    bool result = reqToBeSigned.Verify();
    Console.WriteLine($"PKCS#10 certification request verification status: {result}");
    switch (result)
    {
        case true:
            {
                Console.WriteLine("Retrieving PKCS#12 container...");
                var pfxBytes = File.ReadAllBytes(_PFXFileName);
                Console.WriteLine($"PKCS#12 container successfully retrieved from file \"{_PFXFileName}\"");
                var builder = new Pkcs12StoreBuilder();
                builder.SetUseDerEncoding(true);
                var store = builder.Build();
                var m = new MemoryStream(pfxBytes);
                store.Load(m, _PFXPass.ToCharArray());
                m.Close();
                AsymmetricKeyEntry prkBag = store.GetKey("prk");
                Console.WriteLine("Privtate key successfully retrieved from PKCS#12 container!");
                X509CertificateEntry certBag = store.GetCertificate("cert");
                Console.WriteLine("x509 certificate successfully retrieved from PKCS#12 container!");
                Console.WriteLine("Generating x509 certificate...");
                Console.WriteLine("Generating serial number...");
                Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
                Console.WriteLine($"Certificate serial number: {Convert.ToHexString(serial.ToByteArrayUnsigned())}");
                var certGen = new X509V3CertificateGenerator();
                certGen.SetSerialNumber(serial);
                certGen.SetIssuerDN(certBag.Certificate.IssuerDN);
                certGen.SetNotBefore(DateTime.UtcNow);
                certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
                certGen.SetPublicKey(reqToBeSigned.GetPublicKey());
                certGen.SetSubjectDN(reqToBeSigned.GetCertificationRequestInfo().Subject);
                var nonCritycal = reqToBeSigned.GetRequestedExtensions().GetNonCriticalExtensionOids();
                var Critycal = reqToBeSigned.GetRequestedExtensions().GetCriticalExtensionOids();
                var reqExt = reqToBeSigned.GetRequestedExtensions();
                var nc = nonCritycal.GetEnumerator();
                var cr = Critycal.GetEnumerator();
                while (nc.MoveNext())
                {
                    var ext = reqExt.GetExtension((DerObjectIdentifier)nc.Current);
                    certGen.AddExtension((DerObjectIdentifier)nc.Current, false, ext.GetParsedValue());
                }
                while (cr.MoveNext())
                {
                    var ext = reqExt.GetExtension((DerObjectIdentifier)cr.Current);
                    certGen.AddExtension((DerObjectIdentifier)cr.Current, true, ext.GetParsedValue());
                }
                ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prkBag.Key);
                var x509 = certGen.Generate(signatureFactory);
                Console.WriteLine("x509 certificate successfully issued!");
                Console.WriteLine("Verifying issued x509 certificate");
                bool flag;
                try
                {
                    x509.Verify(certBag.Certificate.GetPublicKey());
                    flag = true;
                }
                catch
                {
                    flag = false;
                }
                Console.WriteLine($"Issued x509 certificate verification status: {flag}");
                switch (flag)
                {
                    case true:
                        {
                            WritePemObject(x509, _IssuedCertFileName);
                            Console.WriteLine($"Issued x509 certificate successfully exported to file \"{_IssuedCertFileName}\"");
                            break;
                        }
                }

                break;
            }
    }
}

static void Sample_11_SignCRL(string _CrlFileName, string _PFXFileName, string _PFXPass)
{
    Console.WriteLine("\nSample_11_SignCRL");
    var secureRandom = new SecureRandom();
    Console.WriteLine("Retrieving PKCS#12 container...");
    var pfxBytes = File.ReadAllBytes(_PFXFileName);
    var builder = new Pkcs12StoreBuilder();
    builder.SetUseDerEncoding(true);
    var store = builder.Build();
    var m = new MemoryStream(pfxBytes);
    store.Load(m, _PFXPass.ToCharArray());
    m.Close();
    AsymmetricKeyEntry prkBag = store.GetKey("prk");
    Console.WriteLine("Privtate key successfully retrieved from PKCS#12 container!");
    X509CertificateEntry certBag = store.GetCertificate("cert");
    Console.WriteLine("x509 certificate successfully retrieved from PKCS#12 container!");
    Org.BouncyCastle.X509.X509V2CrlGenerator CrlGen = new Org.BouncyCastle.X509.X509V2CrlGenerator();
    CrlGen.SetIssuerDN(certBag.Certificate.IssuerDN);
    CrlGen.SetThisUpdate(DateTime.Now);
    CrlGen.SetNextUpdate(DateTime.Now.AddDays(1));
    //Генерируем рандомный серийник, который включим в CRL
    Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
    Console.WriteLine($"Certificate serial number that will be added in CRL: {Convert.ToHexString(serial.ToByteArrayUnsigned())}");
    CrlGen.AddCrlEntry(serial, DateTime.Now, CrlReason.KeyCompromise);
    ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prkBag.Key);
    Console.WriteLine("Generating CRL...");
    X509Crl crl = CrlGen.Generate(signatureFactory);
    Console.WriteLine("CRL generated!");
    Console.WriteLine("Verifying CRL...");
    bool flag;
    try
    {
        crl.Verify(certBag.Certificate.GetPublicKey());
        flag = true;
    }
    catch
    {
        flag = false;
    }
    Console.WriteLine($"CRL verification result: {flag}");
    switch (flag)
    {
        case true:
            {
                WritePemObject(crl, _CrlFileName);
                Console.WriteLine($"CRL successfully exported to file \"{_CrlFileName}\"");
                break;
            }
    }
}

static void Sample_12_CreateOCSPRequest(string _CertFileName, string _RootCertFileName, string _OCSPRequestFileName) {
    Console.WriteLine("\nSample_12_CreateOCSPRequest");
    var secureRandom = new SecureRandom();
    X509Certificate issuerX509 = new X509Certificate(File.ReadAllBytes(_RootCertFileName));
    X509Certificate cert = new X509Certificate(Convert.FromBase64String("MIIEGDCCA8WgAwIBAgIQNkpz3+fcTpZDZTHBAYu0kTAKBggqhQMHAQEDAjBWMQswCQYDVQQGEwJSVTEPMA0GA1UEBwwGTW9zY293MQ4wDAYDVQQLDAVESVZJUDESMBAGA1UECgwJQ3J5cHRvUHJvMRIwEAYDVQQDDAlVQyA5NzIgQ0EwHhcNMjMxMTA5MTQ0MTM2WhcNMjUwMjA5MTQ1MTM2WjCBnzELMAkGA1UEBhMCUlUxFTATBgNVBAcMDNCc0L7RgdC60LLQsDElMCMGA1UECgwc0J7QntCeICLQmtCg0JjQn9Ci0J4t0J/QoNCeIjETMBEGA1UECwwK0JTQmNCS0JjQnzE9MDsGA1UEAww00J/QtdGA0YPQvdC+0LIg0JDQu9C10LrRgdC10Lkg0JDQvdCw0YLQvtC70YzQtdCy0LjRhzBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEDgf23YRRpsw8PpKoVxBVtVacUKZrSyjCzzdr3pXQBOHye4AL9M08OwXa0o/9PdArSo2k0IDDQwfvpgpuCLjOv6o4ICHDCCAhgwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMIGRBggrBgEFBQcBAQSBhDCBgTAvBggrBgEFBQcwAYYjaHR0cDovL3BhYS05NzItdWMtc3ZjL29jc3Avb2NzcC5zcmYwTgYIKwYBBQUHMAKGQmh0dHA6Ly9wYWEtOTcyLXVjL2FpYS9FMzQ4Rjk3QjRERUFGMTI3MzRGOTZBRTU2MzM3RUM0NjIxMzQ1OUZGLmNydDAOBgNVHQ8BAf8EBAMCA+gwIAYJKwYBBAGCNxUHBBMwEQYJKoUDAgIuAAgBAgEBAgEAMFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9wYWEtOTcyLXVjL2NkcC9FMzQ4Rjk3QjRERUFGMTI3MzRGOTZBRTU2MzM3RUM0NjIxMzQ1OUZGLmNybDCBjwYDVR0jBIGHMIGEgBTjSPl7TerxJzT5auVjN+xGITRZ/6FapFgwVjELMAkGA1UEBhMCUlUxDzANBgNVBAcMBk1vc2NvdzEOMAwGA1UECwwFRElWSVAxEjAQBgNVBAoMCUNyeXB0b1BybzESMBAGA1UEAwwJVUMgOTcyIENBghBTKvRKa64HskuN0yh0qCAlMB0GA1UdDgQWBBQNfnYONJ3aW2jHkOXdWvWV7fox9DArBgNVHRAEJDAigA8yMDIzMTEwOTE0NDEzNlqBDzIwMjUwMjA5MTQ1MTM2WjAKBggqhQMHAQEDAgNBALfToZ0zC338PBtBxpXMihNHXKs+7nM2XcqSe+GYhGjIi3fOd8VuZ61GfKR84WX6/BAne/b4JwqI56oQaXuysnA="));
    Console.WriteLine($"x509 certificate successfully retrieved from file \"{_CertFileName}\"");
    Console.WriteLine("Generating OCSP request...");
    var ocspRequestBuilder = new OcspReqGenerator();
    Org.BouncyCastle.Math.BigInteger serial = cert.SerialNumber;
    Console.WriteLine($"Certificate serial number: {Convert.ToHexString(serial.ToByteArrayUnsigned())}");
    byte[] nonce = Org.BouncyCastle.Math.BigInteger.One.ToByteArray();
    X509Extension OCSPNonce = new X509Extension(false, new DerOctetString(nonce));
    IDictionary<DerObjectIdentifier, X509Extension> x509ExtensionsDic = new Dictionary<DerObjectIdentifier, X509Extension>();
    x509ExtensionsDic.Add(OcspObjectIdentifiers.PkixOcspNonce, OCSPNonce);
    ocspRequestBuilder.AddRequest(
        new CertificateID(
            //"1.3.14.3.2.26",
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id,
            issuerX509,
            Org.BouncyCastle.Math.BigInteger.Four),
        new X509Extensions(x509ExtensionsDic)
        );
    nonce = Org.BouncyCastle.Math.BigInteger.Two.ToByteArray();
    OCSPNonce = new X509Extension(false, new DerOctetString(nonce));
    x509ExtensionsDic = new Dictionary<DerObjectIdentifier, X509Extension>();
    x509ExtensionsDic.Add(OcspObjectIdentifiers.PkixOcspNonce, OCSPNonce);
    ocspRequestBuilder.AddRequest(
        new CertificateID(
            //"1.3.14.3.2.26",
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id, 
            issuerX509,
            serial),
        new X509Extensions(x509ExtensionsDic)
        );
    nonce = Org.BouncyCastle.Math.BigInteger.Three.ToByteArray();
    OCSPNonce = new X509Extension(false, new DerOctetString(nonce));
    x509ExtensionsDic = new Dictionary<DerObjectIdentifier, X509Extension>();
    x509ExtensionsDic.Add(OcspObjectIdentifiers.PkixOcspNonce, OCSPNonce);
    ocspRequestBuilder.SetRequestExtensions(new X509Extensions(x509ExtensionsDic));
    var ocspRequest = ocspRequestBuilder.Generate();
    Console.WriteLine("OCSP request generated!");
    File.WriteAllBytes(_OCSPRequestFileName, ocspRequest.GetEncoded());
    Console.WriteLine($"OCSP request successfully expoerted to file \"{_OCSPRequestFileName}\"");
}


static void WritePemObject(Object _object, String _fileName)
{
    TextWriter TextWriter = File.CreateText($"{_fileName}");
    var PemWriter = new PemWriter(TextWriter);
    PemWriter.WriteObject(_object);
    TextWriter.Flush();
    TextWriter.Close();
    TextWriter.Dispose();
}

static System.Object ReadPemObject(String _fileName)
{
    TextReader TextReader = File.OpenText($"{_fileName}");
    var PemReader = new PemReader(TextReader);
    var _object = PemReader.ReadObject();
    TextReader.Close();
    TextReader.Dispose();
    return _object;
}

























//using Org.BouncyCastle.Pkcs;
//using Org.BouncyCastle.OpenSsl;
//using Org.BouncyCastle.X509;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Security;
//using Org.BouncyCastle.Crypto.Parameters;
//using Org.BouncyCastle.Asn1.Ess;
//using Org.BouncyCastle.Asn1;
//using Org.BouncyCastle.Asn1.X509;
//using Org.BouncyCastle.Asn1.Pkcs;
//using Org.BouncyCastle.Asn1.Cms;
//using Org.BouncyCastle.Cms;
//using Org.BouncyCastle.X509.Store;
//using Org.BouncyCastle.Asn1.CryptoPro;
//using Org.BouncyCastle.Crypto.Generators;
//using Org.BouncyCastle.Crypto.Signers;
//using Org.BouncyCastle.Utilities.Encoders;
//using Org.BouncyCastle.Crypto.Operators;
//using Org.BouncyCastle.Asn1.Rosstandart;
//using System.Text;
//using System.Collections;
//using Org.BouncyCastle.Asn1.X500;

//var secureRandom = new SecureRandom();
//var curve = ECGost3410NamedCurves.GetByName("GostR3410-2001-CryptoPro-XchA");
//var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
//var ECGost3410Parameters = new ECGost3410Parameters(
//    new ECNamedDomainParameters(
//        new DerObjectIdentifier("1.2.643.2.2.36.0"),
//        domainParameters),
//    new DerObjectIdentifier("1.2.643.2.2.36.0"),
//    new DerObjectIdentifier("1.2.643.7.1.1.2.2"),
//    null
//);
//var ECKeyGenerationParameters = new ECKeyGenerationParameters(ECGost3410Parameters, secureRandom);
//var keyGenerator = new ECKeyPairGenerator();
//keyGenerator.Init(ECKeyGenerationParameters);
//var keyPair = keyGenerator.GenerateKeyPair();
//var hashCode = DigestUtilities.CalculateDigest(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, Encoding.ASCII.GetBytes("Hello, world!!!"));
//var signer = new ECGost3410Signer();
//var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)keyPair.Private, secureRandom);
//signer.Init(true, paramsWithRandom);
//Org.BouncyCastle.Math.BigInteger[] signature;
//do
//{
//    signature = signer.GenerateSignature(hashCode);
//} while ((signature[0].SignValue != 1) && (signature[1].SignValue != 1));
//signer.Init(false, (AsymmetricKeyParameter)keyPair.Public);
//var verificationResult = signer.VerifySignature(hashCode, signature[0], signature[1]);
//Console.WriteLine(verificationResult);

//X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
//extGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.DataEncipherment));
//extGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
//var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256), ((ECPublicKeyParameters)(keyPair.Public)).Q.GetEncoded());
//var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);
//extGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));
//AttributePkcs attributePkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
//ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)keyPair.Private);
//var subjectNameOidList = new List<DerObjectIdentifier>();
//subjectNameOidList.Add(X509Name.CN);
//subjectNameOidList.Add(X509Name.L);
//subjectNameOidList.Add(new DerObjectIdentifier("1.2.643.100.3"));
//subjectNameOidList.Add(X509Name.E);
//var subjectNameAsn1Vector = new Asn1EncodableVector();
//foreach (DerObjectIdentifier oid in subjectNameOidList)
//{
//    AttributeTypeAndValue attributeAndTypeValue = null;
//    switch (oid) {
//        case DerObjectIdentifier value when value.Equals(X509Name.CN):
//            {
//                attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerUtf8String("Даров"));
//                break;
//            }
//        case DerObjectIdentifier value when value.Equals(X509Name.L):
//            {
//                attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerUtf8String("Это Москва, детка!"));
//                break;
//            }
//        case DerObjectIdentifier value when value.Equals(new DerObjectIdentifier("1.2.643.100.3")):
//            {
//                attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerNumericString(Encoding.ASCII.GetBytes("123456780901")));
//                break;
//            }
//        case DerObjectIdentifier value when value.Equals(X509Name.E):
//            {
//                System.Globalization.IdnMapping idn = new System.Globalization.IdnMapping();
//                //Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
//                //var enc = Encoding.GetEncoding("windows-1251");
//                var newEmail = Encoding.Unicode.GetString(Encoding.Convert(Encoding.UTF8, Encoding.Unicode, Encoding.UTF8.GetBytes("привет_мир@рф.рф")));
//                var email = idn.GetAscii(newEmail);
//                attributeAndTypeValue = new AttributeTypeAndValue(oid, new DerIA5String(email, true));
//                break;
//            }
//    }
//    subjectNameAsn1Vector.Add(new DerSet(attributeAndTypeValue));
//}
//subjectNameAsn1Vector.Reverse();
//var subjectName = new DerSequence(subjectNameAsn1Vector);
//Console.WriteLine(Convert.ToBase64String(subjectName.GetDerEncoded()));
//Console.WriteLine();
//X509Name subject = X509Name.GetInstance(subjectName.GetDerEncoded());
//var request = new Pkcs10CertificationRequest(
//    signatureFactory,
//    subject,
//    (AsymmetricKeyParameter)keyPair.Public,
//    new DerSet(attributePkcs)
//);
//Console.WriteLine(Convert.ToBase64String(request.GetEncoded()));
//verificationResult = request.Verify();
//Console.WriteLine(verificationResult);
