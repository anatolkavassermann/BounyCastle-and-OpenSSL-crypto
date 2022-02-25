//New IText
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

//.Net Framework 4.8
using System.Text;
using System.Collections;
using System.Xml;


//BC 1.9.0
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
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Asn1.Rosstandart;

//BC XML
using Org.BouncyCastle.Crypto.Xml;

//ASN.1 Reader
using Net.Asn1.Reader;

//For CAdES BES
var ToBeSigned = "Hello, world!";
var ToBeSignedFileName = "toBeSigned.txt";
File.WriteAllBytes(ToBeSignedFileName, Encoding.ASCII.GetBytes(ToBeSigned));

//For XMLSSIG
string ExampleXml = @"<?xml version=""1.0""?>
<ToBeSigned>
<Data>Hello, world!</Data>
</ToBeSigned>";
XmlDocument doc = new XmlDocument();
doc.LoadXml(ExampleXml);
var XMLToBeSignedFileName = "XMLtoBeSigned.xml";
doc.Save(XMLToBeSignedFileName);

//For PAdES
var PDFToBeSignedFileName = "PDFtoBeSigned.pdf";

//keydata
var PrKeyFileName = "prk.pem";
var PbKeyFileName = "pbk.pem";

//Rawsig FileName
var RawSigFileName = "toBeSignedRaw.sig";

//For CA
var CertRequestFileName = "req.req";
var SelfSignedCertFileName = "cert.crt";
var IssuedCertFileName = "issued_cert.crt";
var cpro = "certnew.cer";
var CrlFileName = "crl.crl";

//For PFX
var PFXFileName = "pfx.pfx";
var PFXPass = "12345qwerty";

//For CAdES, XMLDSIG and PAdES
var CAdESBES_SigFileName = "toBeSigned_CAdESBES.sig";
var XMLDSIG_SigFileName = "XMLtoBeSigned_XMLDSIG.signed.xml";
var PAdES_SigFileName = "PDFtoBeSigned_PAdES.signed.pdf";

//For export certs from cpro key container
var Header_Key_FileName = "header.key";

Sample_1_Generate_Gost3410_2012_KeyPair(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_2_Read_Gost3410_2012_KeyPair_FromFile(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_3_Sign_And_Export_RawSignature_ToFile(PrKeyFileName, PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_4_ImportandVerify_RawSignature(PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_5_GenerateCertRequest(PrKeyFileName, PbKeyFileName, CertRequestFileName);
Sample_6_GenerateSelfSignedCertificate(PrKeyFileName, PbKeyFileName, SelfSignedCertFileName);
Sample_7_ExportPfx(PrKeyFileName, PFXFileName, SelfSignedCertFileName, PFXPass);
Sample_8_ImportPfx(PFXFileName, PFXPass);
Sample_9_SignCertRequest(PFXFileName, PFXPass, CertRequestFileName, IssuedCertFileName);
Sample_10_Create_Attached_CAdES_BES(PFXFileName, PFXPass, CAdESBES_SigFileName, ToBeSignedFileName);
Sample_11_Verify_Attached_CAdES_BES(CAdESBES_SigFileName);
Sample_12_SignCRL(CrlFileName, PFXFileName, PFXPass);
Sample_13_CreateXMLDSig(PFXFileName, PFXPass, XMLDSIG_SigFileName, XMLToBeSignedFileName);
Sample_14_VerifyXMLDSig(XMLDSIG_SigFileName);
Sample_15_CreatePAdES_usingTables(PFXFileName, PFXPass, "Tables.pdf", PDFToBeSignedFileName);
System.Threading.Thread.Sleep(1000);
Sample_15_CreatePAdES(PFXFileName, PFXPass, PAdES_SigFileName, PDFToBeSignedFileName);
Sample_16_VerifyPAdES(PAdES_SigFileName);
Sample_16_VerifyPAdES("Tables.pdf");

static void Sample_1_Generate_Gost3410_2012_KeyPair(string _PrKeyFileName, string _PbKeyFileName, string _ToBeSigned)
{
	Console.WriteLine("\nSample_1_Generate_Gost3410_2012_KeyPair");
	var secureRandom = new SecureRandom();
	var curve = ECGost3410NamedCurves.GetByNameX9("Tc26-Gost-3410-12-256-paramSetA");
	var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
	var ECGost3410Parameters = new ECGost3410Parameters(
		new ECNamedDomainParameters(new DerObjectIdentifier("1.2.643.7.1.2.1.1.1"), domainParams),
		new DerObjectIdentifier("1.2.643.7.1.2.1.1.1"),
		new DerObjectIdentifier("1.2.643.7.1.1.2.2"),
		null
	);
	var ECKeyGenerationParameters = new ECKeyGenerationParameters(ECGost3410Parameters, secureRandom);
	var keyGenerator = new ECKeyPairGenerator();
	keyGenerator.Init(ECKeyGenerationParameters);
	var keyPair = keyGenerator.GenerateKeyPair();
	var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), Encoding.ASCII.GetBytes(_ToBeSigned));
	var signer = new ECGost3410Signer();
	var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)keyPair.Private, secureRandom);
	signer.Init(true, paramsWithRandom);
	Org.BouncyCastle.Math.BigInteger[] signature;
	do
	{
		signature = signer.GenerateSignature(hashCode);
	} while ((signature[0].SignValue != 1) && (signature[1].SignValue != 1));
	signer.Init(false, (AsymmetricKeyParameter)keyPair.Public);
	switch (signer.VerifySignature(hashCode, signature[0], signature[1]))
	{
		case true:
			{
				WritePemObject(keyPair.Private, _PrKeyFileName);
				WritePemObject(keyPair.Public, _PbKeyFileName);
				Console.WriteLine("Key pair generated!");
				Console.WriteLine("Key pair exported!");
				break;
			}
		default:
			{
				Console.WriteLine("Key pair not generated!");
				Console.WriteLine("Key pair not exported!");
				break;
			}
	}
}

static void Sample_2_Read_Gost3410_2012_KeyPair_FromFile(string _PrKeyFileName, string _PbKeyFileName, string _ToBeSigned)
{
	Console.WriteLine("\nSample_2_Read_Gost3410_2012_KeyPair_FromFile");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
	var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), Encoding.ASCII.GetBytes(_ToBeSigned));
	var signer = new ECGost3410Signer();
	var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)prk, secureRandom);
	signer.Init(true, paramsWithRandom);
	var signature = signer.GenerateSignature(hashCode);
	signer.Init(false, (AsymmetricKeyParameter)pbk);
	bool result = signer.VerifySignature(hashCode, signature[0], signature[1]);
	Console.WriteLine($"Key pair match: {result}");
	switch (result)
	{
		case true:
			{
				Console.WriteLine("Key pair imported");
				break;
			}
		default:
			{
				Console.WriteLine("Key pair not imported");
				break;
			}
	}
}

static void Sample_3_Sign_And_Export_RawSignature_ToFile(string _PrKeyFileName, string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
{
	Console.WriteLine("\nSample_3_Export_RawSignature_ToFile");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
	var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), File.ReadAllBytes(_ToBeSignedFileName));
	var signer = new ECGost3410Signer();
	var paramsWithRandom = new ParametersWithRandom((AsymmetricKeyParameter)prk, secureRandom);
	signer.Init(true, paramsWithRandom);
	var signature = signer.GenerateSignature(hashCode);
	signer.Init(false, (AsymmetricKeyParameter)pbk);
	bool result = signer.VerifySignature(hashCode, signature[0], signature[1]);
	Console.WriteLine($"Key pair match: {result}\nSignature verified: {result}");
	switch (result)
	{
		case true:
			{
				List<byte> sig = new List<byte>();
				sig.AddRange(signature[0].ToByteArrayUnsigned());
				sig.AddRange(signature[1].ToByteArrayUnsigned());
				File.WriteAllBytes(_RawSigFileName, sig.ToArray());
				Console.WriteLine("Raw signature exported");
				break;
			}
		default:
			{
				Console.WriteLine("Raw signature not exported");
				break;
			}
	}
}

static void Sample_4_ImportandVerify_RawSignature(string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
{
	Console.WriteLine("\nSample_4_ImportandVerify_RawSignature");
	var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), File.ReadAllBytes(_ToBeSignedFileName));
	byte[] signatureBytes = File.ReadAllBytes(_RawSigFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
	Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(signatureBytes.Take(32).ToArray());
	Org.BouncyCastle.Math.BigInteger s = new Org.BouncyCastle.Math.BigInteger(signatureBytes.Skip(32).Take(32).ToArray());
	var signer = new ECGost3410Signer();
	signer.Init(false, (AsymmetricKeyParameter)pbk);
	var result = signer.VerifySignature(hashCode, r, s);
	Console.WriteLine($"Raw signature verification status: {result}");
	switch (result)
	{
		case true:
			{
				Console.WriteLine("Signature verified OK");
				break;
			}
		default:
			{
				Console.WriteLine("Signature NOT verified");
				break;
			}
	}
}

static void Sample_5_GenerateCertRequest(string _PrKeyFileName, string _PbKeyFileName, string _CertRequestFileName)
{
	Console.WriteLine("\nSample_5_GenerateCertRequest");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
	X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();
	extGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(240));
	extGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
	var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id), pbk.Q.GetEncoded());
	var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);
	extGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));
	AttributePkcs attributePkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
	var request = new Pkcs10CertificationRequest(
		"1.2.643.7.1.1.3.2",
		new X509Name("CN=Месенгисер Якоб, L=Москва"),
		(ECPublicKeyParameters)pbk,
		new DerSet(attributePkcs),
		(ECPrivateKeyParameters)prk);
	var result = request.Verify(pbk);
	switch (result)
	{
		case true:
			{
				Console.WriteLine("Certificate request generated!");
				WritePemObject(request, _CertRequestFileName);
				break;
			}
		default:
			{
				Console.WriteLine("Certificate request NOT generated!");
				break;
			}
	}

}

static void Sample_6_GenerateSelfSignedCertificate(string _PrKeyFileName, string _PbKeyFileName, string _SelfSignedCertFileName)
{
	Console.WriteLine("\nSample_6_GenerateSelfSignedCertificate");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);

	Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
	var certGen = new X509V3CertificateGenerator();
	certGen.SetSerialNumber(serial);
	certGen.SetIssuerDN(new X509Name("CN=Месенгисер Якоб"));
	certGen.SetNotBefore(DateTime.UtcNow);
	certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
	certGen.SetPublicKey(pbk);
	certGen.SetSubjectDN(new X509Name("CN=Месенгисер Якоб"));

	var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier("1.2.643.7.1.2.1.1.1"), pbk.Q.GetEncoded());
	var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);

	certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(240));
	certGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
	certGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));

	var pbkParams = (ECGost3410Parameters)pbk.Parameters;
	ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prk);
	var x509 = certGen.Generate(signatureFactory);
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
	switch (flag)
	{
		case true:
			{
				WritePemObject(x509, _SelfSignedCertFileName);
				Console.WriteLine("Self-signed certificate generated");
				break;
			}
		default:
			{
				Console.WriteLine("Self-signed certificate NOT generated");
				break;
			}
	}
}

static void Sample_7_ExportPfx(string _PrKeyFileName, string _PFXFileName, string _CertFileName, string _PFXPass)
{
	Console.WriteLine("\nSample_7_ExportPfx");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	X509Certificate x509 = (X509Certificate)ReadPemObject(_CertFileName);
	var alias = x509.SubjectDN.GetValueList(new DerObjectIdentifier("2.5.4.3"));
	var pkcs12Builder = new Pkcs12StoreBuilder();
	pkcs12Builder.SetUseDerEncoding(true);
	var store = pkcs12Builder.Build();
	store.SetKeyEntry("prk", new AsymmetricKeyEntry((AsymmetricKeyParameter)prk), new X509CertificateEntry[] { new X509CertificateEntry(x509) });
	store.SetCertificateEntry("cert", new X509CertificateEntry(x509));
	var m = new MemoryStream();
	store.Save(m, _PFXPass.ToCharArray(), secureRandom);
	var data = m.ToArray();
	var pkcs12Bytes = Pkcs12Utilities.ConvertToDefiniteLength(data);
	File.WriteAllBytes(_PFXFileName, pkcs12Bytes);
	Console.WriteLine("PFX exported!");
}

static void Sample_8_ImportPfx(string _PFXFileName, string _PFXPass)
{
	Console.WriteLine("\nSample_8_ImportPfx");
	var secureRandom = new SecureRandom();
	try
	{
		var pfxBytes = File.ReadAllBytes(_PFXFileName);
		var builder = new Pkcs12StoreBuilder();
		builder.SetUseDerEncoding(true);
		var store = builder.Build();
		var m = new MemoryStream(pfxBytes);
		store.Load(m, _PFXPass.ToCharArray());
		m.Close();
		var prkBag = store.GetKey("prk");
		var certBag = store.GetCertificate("cert");
		string testString = "Hello, world!";
		var hashCode = DigestUtilities.CalculateDigest(new DerObjectIdentifier("1.2.643.7.1.1.2.2"), Encoding.ASCII.GetBytes(testString));
		var signer = new ECGost3410Signer();
		var paramsWithRandom = new ParametersWithRandom(prkBag.Key, secureRandom);
		signer.Init(true, paramsWithRandom);
		var signature = signer.GenerateSignature(hashCode);
		signer.Init(false, certBag.Certificate.GetPublicKey());
		var result = signer.VerifySignature(hashCode, signature[0], signature[1]);
		Console.WriteLine("PFX key pair match: " + result);
		switch (result)
		{
			case true:
				{
					Console.WriteLine("PFX imported!");
					break;
				}
			default:
				{
					Console.WriteLine("PFX NOT imported!");
					break;
				}
		}

	}
	catch
	{
		Console.WriteLine("PFX NOT imported!");
	}
}

static void Sample_9_SignCertRequest(string _PFXFileName, string _PFXPass, string _CertRequestFileName, string _IssuedCertFileName)
{
	Console.WriteLine("\nSample_9_SignCertRequest");
	var secureRandom = new SecureRandom();
	Pkcs10CertificationRequest reqToBeSigned = (Pkcs10CertificationRequest)ReadPemObject(_CertRequestFileName);
	bool result = reqToBeSigned.Verify();
	Console.WriteLine($"PKCS#10 verification status: {result}");
	switch (result)
	{
		case true:
			{
				var pfxBytes = File.ReadAllBytes(_PFXFileName);
				var builder = new Pkcs12StoreBuilder();
				builder.SetUseDerEncoding(true);
				var store = builder.Build();
				var m = new MemoryStream(pfxBytes);
				store.Load(m, _PFXPass.ToCharArray());
				m.Close();
				AsymmetricKeyEntry prkBag = store.GetKey("prk");
				X509CertificateEntry certBag = store.GetCertificate("cert");
				Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
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
				switch (flag)
				{
					case true:
						{
							WritePemObject(x509, _IssuedCertFileName);
							Console.WriteLine("Certificate issued");
							break;
						}
					default:
						{
							Console.WriteLine("Certificate NOT issued");
							break;
						}
				}

				break;
			}
		default:
			{
				Console.WriteLine("Certificate NOT issued!");
				break;
			}
	}
}

static void Sample_10_Create_Attached_CAdES_BES(string _PFXFileName, string _PFXPass, string _CAdES_BES_SigFileName, string _ToBeSignedFileName)
{
	Console.WriteLine("\nSample_10_Create_CAdES_BES");
	var pfxBytes = File.ReadAllBytes(_PFXFileName);
	var builder = new Pkcs12StoreBuilder();
	builder.SetUseDerEncoding(true);
	var store = builder.Build();
	var m = new MemoryStream(pfxBytes);
	store.Load(m, _PFXPass.ToCharArray());
	m.Close();
	AsymmetricKeyEntry prkBag = store.GetKey("prk");
	X509CertificateEntry certBag = store.GetCertificate("cert");
	var fileBytes = File.ReadAllBytes(_ToBeSignedFileName);
	List<Org.BouncyCastle.X509.X509Certificate> certList = new List<Org.BouncyCastle.X509.X509Certificate>();
	certList.Add(certBag.Certificate);
	var storeParams = new X509CollectionStoreParameters(certList);
	var certStore = X509StoreFactory.Create("Certificate/Collection", storeParams);
	var publicKey = (ECPublicKeyParameters)certBag.Certificate.GetPublicKey();
	var publicKeyParams = (ECGost3410Parameters)publicKey.Parameters;
	var certHash = DigestUtilities.CalculateDigest(publicKeyParams.DigestParamSet.Id, certBag.Certificate.GetEncoded());
	var essV2Cert = new EssCertIDv2(
		new AlgorithmIdentifier(publicKeyParams.DigestParamSet.Id),
		certHash,
		new IssuerSerial(
			new GeneralNames(
				new GeneralName(certBag.Certificate.IssuerDN)
			),
			new DerInteger(certBag.Certificate.SerialNumber)
		)
	);
	var signingCertV2 = new SigningCertificateV2(new EssCertIDv2[] { essV2Cert });
	var fileHash = DigestUtilities.CalculateDigest(publicKeyParams.DigestParamSet.Id, fileBytes);
	var essattb = new Org.BouncyCastle.Asn1.Cms.Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(signingCertV2));
	var timeattb = new Org.BouncyCastle.Asn1.Cms.Attribute(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new DerUtcTime(DateTime.UtcNow)));
	var ctattb = new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(new DerObjectIdentifier("1.2.840.113549.1.7.1")));
	var mdattb = new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(fileHash)));
	var daattb = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(PkcsObjectIdentifiers.DigestAlgorithm), new DerSet(new DerObjectIdentifier(publicKeyParams.DigestParamSet.Id)));

	var signedAttrs = new Hashtable();
	signedAttrs.Add((DerObjectIdentifier)essattb.AttrType, essattb);
	signedAttrs.Add((DerObjectIdentifier)timeattb.AttrType, timeattb);
	signedAttrs.Add((DerObjectIdentifier)ctattb.AttrType, ctattb);
	signedAttrs.Add((DerObjectIdentifier)mdattb.AttrType, mdattb);
	signedAttrs.Add((DerObjectIdentifier)daattb.AttrType, daattb);

	var signedAttributesTable = new Org.BouncyCastle.Asn1.Cms.AttributeTable(signedAttrs);
	var signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
	CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
	gen.UseDerForCerts = true;
	gen.AddCertificates(certStore);
	gen.AddSigner((AsymmetricKeyParameter)prkBag.Key, certBag.Certificate, publicKeyParams.DigestParamSet.Id, signedAttributeGenerator, null);
	var message = new CmsProcessableByteArray(fileBytes);

	var attachedCAdESBES = gen.Generate(message, true);
	var encodedSignedData = attachedCAdESBES.GetEncoded("DER");
	var convertedSignedData = Convert.ToBase64String(encodedSignedData);
	File.WriteAllBytes(_CAdES_BES_SigFileName, Encoding.ASCII.GetBytes(convertedSignedData));
	Console.WriteLine("CAdES-BES generated");
}

static void Sample_11_Verify_Attached_CAdES_BES(string _CAdES_BES_SigFileName)
{
	Console.WriteLine("\nSample_11_Verify_CAdES_BES");
	var signatureBytes = File.ReadAllBytes(_CAdES_BES_SigFileName);
	CmsSignedData cmsSignedData;
	try
	{
		cmsSignedData = new CmsSignedData(signatureBytes);
	}
	catch
	{
		cmsSignedData = new CmsSignedData(Base64.Decode(signatureBytes));
	}
	Console.WriteLine($"Signed Content: {Encoding.ASCII.GetString((byte[])cmsSignedData.SignedContent.GetContent())}");
	var certStoreInSig = cmsSignedData.GetCertificates("collection");
	ICollection sgnrs = cmsSignedData.GetSignerInfos().GetSigners();
	var e = sgnrs.GetEnumerator();
	while (e.MoveNext())
	{
		var sgnr = (SignerInformation)e.Current;
		var certs = certStoreInSig.GetMatches(sgnr.SignerID);
		var ee = certs.GetEnumerator();
		while (ee.MoveNext())
		{
			var cert = (Org.BouncyCastle.X509.X509Certificate)ee.Current;
			bool reslt = sgnr.Verify(cert);
			Console.WriteLine($"CAdES verification status: {reslt}");
			var encodedSignedAttributes = sgnr.GetEncodedSignedAttributes();
			var sig = sgnr.GetSignature();
			var publicKey = (ECPublicKeyParameters)cert.GetPublicKey();
			var publicKeyParams = (ECGost3410Parameters)publicKey.Parameters;
			var encodedSignedAttributesHash = DigestUtilities.CalculateDigest(publicKeyParams.DigestParamSet.Id, encodedSignedAttributes);
			var r = new Org.BouncyCastle.Math.BigInteger(1, sig, 32, 32);
			var s = new Org.BouncyCastle.Math.BigInteger(1, sig, 0, 32);
			var gostVerifier = new ECGost3410Signer();
			gostVerifier.Init(false, publicKey);
			Console.WriteLine($"Manual CAdES-BES verification status: {gostVerifier.VerifySignature(encodedSignedAttributesHash, r, s)}");
		}
	}
}

static void Sample_12_SignCRL(string _CrlFileName, string _PFXFileName, string _PFXPass)
{
	Console.WriteLine("\nSample_12_SignCRL");
	var secureRandom = new SecureRandom();
	var pfxBytes = File.ReadAllBytes(_PFXFileName);
	var builder = new Pkcs12StoreBuilder();
	builder.SetUseDerEncoding(true);
	var store = builder.Build();
	var m = new MemoryStream(pfxBytes);
	store.Load(m, _PFXPass.ToCharArray());
	m.Close();
	AsymmetricKeyEntry prkBag = store.GetKey("prk");
	X509CertificateEntry certBag = store.GetCertificate("cert");
	Org.BouncyCastle.X509.X509V2CrlGenerator CrlGen = new Org.BouncyCastle.X509.X509V2CrlGenerator();
	CrlGen.SetIssuerDN(certBag.Certificate.IssuerDN);
	CrlGen.SetThisUpdate(DateTime.Now);
	CrlGen.SetNextUpdate(DateTime.Now.AddDays(1));
	CrlGen.AddCrlEntry(certBag.Certificate.SerialNumber, DateTime.Now, CrlReason.Unspecified);
	ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prkBag.Key);
	X509Crl crl = CrlGen.Generate(signatureFactory);
	WritePemObject(crl, _CrlFileName);
	try
	{
		crl.Verify(certBag.Certificate.GetPublicKey());
		Console.WriteLine("CRL generated!");
	}
	catch
	{
		Console.WriteLine("CRL NOT generated!");
	}
}

static void Sample_13_CreateXMLDSig(string _PFXFileName, string _PFXPass, string _XMLDSIG_SigFileName, string _XMLToBeSignedFileName)
{
	Console.WriteLine("\nSample_13_CreateXMLDSig");
	try
	{
		var pfxBytes = File.ReadAllBytes(_PFXFileName);
		var builder = new Pkcs12StoreBuilder();
		builder.SetUseDerEncoding(true);
		var store = builder.Build();
		var m = new MemoryStream(pfxBytes);
		store.Load(m, _PFXPass.ToCharArray());
		m.Close();
		AsymmetricKeyEntry prkBag = store.GetKey("prk");
		X509CertificateEntry certBag = store.GetCertificate("cert");
		XmlDocument document = new XmlDocument();
		document.PreserveWhitespace = true;
		document.Load(_XMLToBeSignedFileName);

		var signedXml = new SignedXml(document)
		{
			SigningKey = (AsymmetricKeyParameter)prkBag.Key,
		};
		var reference = new Reference();
		reference.Uri = "";
		reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
		reference.DigestMethod = SignedXml.XmlDsigGost3411_2012_256_Url;
		signedXml.AddReference(reference);
		signedXml.KeyInfo = new KeyInfo();
		signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certBag.Certificate));
		signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410_2012_256_Url;
		signedXml.ComputeSignature();

		System.Xml.XmlElement xmlDigitalSignature = signedXml.GetXml();
		document.DocumentElement.AppendChild(document.ImportNode(xmlDigitalSignature, true));
		document.Save(_XMLDSIG_SigFileName);
		Console.WriteLine("XMLDSIG created and exported!");
	}
	catch
	{
		Console.WriteLine("XMLDSIG NOT created or NOT exported!");
	}
}

static void Sample_14_VerifyXMLDSig(string _XMLDSIG_SigFileName)
{
	Console.WriteLine("\nSample_14_VerifyXMLDSig");
	XmlDocument document = new XmlDocument();
	document.PreserveWhitespace = true;
	document.Load(_XMLDSIG_SigFileName);

	SignedXml signedXml = new SignedXml(document);
	var signatureNode = (XmlElement)document.GetElementsByTagName("Signature")[0];
	signedXml.LoadXml(signatureNode);
	var result = signedXml.CheckSignature();
	switch (result)
	{
		case true:
			{
				Console.WriteLine("XMLDSIG verified!");
				break;
			}
		default:
			{
				Console.WriteLine("XMLDSIG NOT verified!");
				break;
			}
	}
}

static void Sample_15_CreatePAdES(string _PFXFileName, string _PFXPass, string _PAdES_SigFileName, string _PDFToBeSignedFileName)
{
	try
	{
		Console.WriteLine("\nSample_15_CreatePAdES");
		var pfxBytes = File.ReadAllBytes(_PFXFileName);
		var Pkcs12StoreBuilder = new Pkcs12StoreBuilder();
		Pkcs12StoreBuilder.SetUseDerEncoding(false);
		var store = Pkcs12StoreBuilder.Build();
		var m = new MemoryStream(pfxBytes);
		store.Load(m, _PFXPass.ToCharArray());
		m.Close();
		AsymmetricKeyEntry prkBag = store.GetKey("prk");
		X509CertificateEntry certBag = store.GetCertificate("cert");
		var publicKey = (ECPublicKeyParameters)certBag.Certificate.GetPublicKey();
		var publickeyparams = (ECGost3410Parameters)publicKey.Parameters;
		PdfReader reader = new PdfReader(_PDFToBeSignedFileName);
		PdfWriter writer = new PdfWriter(new FileStream($"{_PDFToBeSignedFileName}.temp", FileMode.Create, FileAccess.ReadWrite), new WriterProperties().SetFullCompressionMode(false)); //решаем проблему со сжатием при наличии в файле Cross-Reference Streams
		PdfDocument toBeSaved = new PdfDocument(reader, writer);
		toBeSaved.Close();
		writer.Close();
		reader.Close();
		reader = new PdfReader($"{_PDFToBeSignedFileName}.temp");
		PdfDocument p = new PdfDocument(reader);
		p.GetDocumentInfo().SetAuthor("Месенгисер Якоб");
		reader = new PdfReader($"{_PDFToBeSignedFileName}.temp");
		PdfDocumentContentParser pcp = new iText.Kernel.Pdf.Canvas.Parser.PdfDocumentContentParser(p);
		TextMarginFinder finder = pcp.ProcessContent(p.GetNumberOfPages(), new iText.Kernel.Pdf.Canvas.Parser.Listener.TextMarginFinder());
		Rectangle datarec = finder.GetTextRectangle();
		PdfSigner signer = new PdfSigner(reader, new FileStream($"{_PAdES_SigFileName}", FileMode.Create, FileAccess.ReadWrite), new StampingProperties().UseAppendMode());
		PdfDocument ppp = signer.GetDocument();
		signer.SetFieldName("Signature1");
		float width = 300f;
		float height = 100f;
		Rectangle sigrec = null;
		if (datarec.GetWidth() < width)
		{
			sigrec = new Rectangle(
				datarec.GetX() - ((width - datarec.GetWidth()) / 2),
				datarec.GetY() - height - 30, width, height
				);
		}
		else if (datarec.GetWidth() == width)
		{
			sigrec = new Rectangle(datarec.GetX(), datarec.GetY() - height - 30, width, height);
		}
		else if (datarec.GetWidth() > width)
		{
			sigrec = new Rectangle(
				datarec.GetX() + ((datarec.GetWidth() - width) / 2),
				datarec.GetY() - height - 30, width, height
				);
		}
		PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
		.SetReason("A")
		.SetLocation("B")
		.SetReuseAppearance(false)
		.SetPageRect(sigrec)
		.SetPageNumber(p.GetNumberOfPages())
		.SetCertificate(certBag.Certificate)
		.SetLayer2Text("");
		PdfFont font = PdfFontFactory.CreateFont(@"C:\Windows\Fonts\times.ttf", "cp1251", iText.Kernel.Font.PdfFontFactory.EmbeddingStrategy.PREFER_EMBEDDED, true);
		PdfCanvas pdfCanvas0 = new PdfCanvas(appearance.GetLayer2(), ppp)
			.SetStrokeColor(iText.Kernel.Colors.ColorConstants.BLUE)
			.RoundRectangle(0, 0, sigrec!.GetWidth(), sigrec.GetHeight(), 10)
			.Stroke();
		Canvas canvas = new Canvas(appearance.GetLayer2(), signer.GetDocument());
		StringBuilder builder = new StringBuilder();
		builder.AppendLine("ДОКУМЕНТ ПОДПИСАН\nЭЛЕКТРОННОЙ ПОДПИСЬЮ");
		Paragraph paragraph1 = new Paragraph(builder.ToString())
			.SetFont(font)
			.SetFontSize(10)
			.SetFontColor(iText.Kernel.Colors.ColorConstants.BLUE)
			.SetTextAlignment(iText.Layout.Properties.TextAlignment.CENTER);
		builder.Clear();
		builder.AppendLine($"Сертификат: {BitConverter.ToString(certBag.Certificate.SerialNumber.ToByteArray()).Replace("-", "").ToLower()}");
		builder.AppendLine($"Владелец: {certBag.Certificate.SubjectDN.GetValueList(new DerObjectIdentifier("2.5.4.3"))[0]}");
		builder.AppendLine($"Действителен с {certBag.Certificate.NotBefore.Date.ToString("d")} по {certBag.Certificate.NotAfter.Date.ToString("d")}");
		Paragraph paragraph2 = new Paragraph(builder.ToString())
			.SetFont(font)
			.SetFontSize(10)
			.SetFontColor(iText.Kernel.Colors.ColorConstants.BLUE);

		canvas.Add(new Div()
			.SetHeight(sigrec!.GetHeight())
			.SetWidth(sigrec!.GetWidth())
			.SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE)
			.SetMarginLeft(10)
			.SetMarginRight(10)
			.Add(paragraph1)
			.Add(paragraph2)
			);
		builder.Clear();
		builder.AppendLine($"Сертификат: {BitConverter.ToString(certBag.Certificate.SerialNumber.ToByteArray()).Replace("-", "").ToLower()}");
		builder.AppendLine($"Владелец: {certBag.Certificate.SubjectDN.GetValueList(new DerObjectIdentifier("2.5.4.3"))[0]}");
		builder.AppendLine($"Действителен с {certBag.Certificate.NotBefore.Date.ToString("d")} по {certBag.Certificate.NotAfter.Date.ToString("d")}");
		canvas.Close();
		iText.Signatures.IExternalSignature pks = new iText.Signatures.PrivateKeySignature(prkBag.Key, publickeyparams.DigestParamSet.Id);
		signer.SignDetached(pks, new X509Certificate[] { certBag.Certificate }, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
		Console.WriteLine("PDF is signed!");
		signer.GetDocument().Close();
		ppp.Close();
		reader.Close();
		writer.Close();
	}
	catch
	{
		Console.WriteLine("PDF is NOT signed!");
	}
}

static void Sample_15_CreatePAdES_usingTables(string _PFXFileName, string _PFXPass, string _PAdES_SigFileName, string _PDFToBeSignedFileName)
{
	try
	{
		Console.WriteLine("\nSample_15_CreatePAdES_usingTables");
		var pfxBytes = File.ReadAllBytes(_PFXFileName);
		var Pkcs12StoreBuilder = new Pkcs12StoreBuilder();
		Pkcs12StoreBuilder.SetUseDerEncoding(false);
		var store = Pkcs12StoreBuilder.Build();
		var m = new MemoryStream(pfxBytes);
		store.Load(m, _PFXPass.ToCharArray());
		m.Close();
		AsymmetricKeyEntry prkBag = store.GetKey("prk");
		X509CertificateEntry certBag = store.GetCertificate("cert");
		var publicKey = (ECPublicKeyParameters)certBag.Certificate.GetPublicKey();
		var publickeyparams = (ECGost3410Parameters)publicKey.Parameters;
		PdfReader reader = new PdfReader(_PDFToBeSignedFileName);
		PdfWriter writer = new PdfWriter(new FileStream($"{_PDFToBeSignedFileName}.temp", FileMode.Create, FileAccess.ReadWrite), new WriterProperties().SetFullCompressionMode(false)); //решаем проблему со сжатием при наличии в файле Cross-Reference Streams
		PdfDocument toBeSaved = new PdfDocument(reader, writer);
		toBeSaved.Close();
		writer.Close();
		reader.Close();
		reader = new PdfReader($"{_PDFToBeSignedFileName}.temp");
		PdfSigner signer = new PdfSigner(reader, new FileStream($"{_PAdES_SigFileName}", FileMode.Create, FileAccess.ReadWrite), new StampingProperties().UseAppendMode());
		signer.GetDocument().GetDocumentInfo().SetAuthor("Месенгисер Якоб");
		PdfDocumentContentParser pcp = new iText.Kernel.Pdf.Canvas.Parser.PdfDocumentContentParser(signer.GetDocument());
		TextMarginFinder finder = pcp.ProcessContent(signer.GetDocument().GetNumberOfPages(), new iText.Kernel.Pdf.Canvas.Parser.Listener.TextMarginFinder());
		Rectangle datarec = finder.GetTextRectangle();
		signer.SetFieldName("Signature1");
		float width = 201f;
		float height = 80f;
		Rectangle sigrec = null;
		if (datarec.GetWidth() < width)
		{
			sigrec = new Rectangle(
				datarec.GetX() - ((width - datarec.GetWidth()) / 2),
				datarec.GetY() - height - 30, width, height
				);
		}
		else if (datarec.GetWidth() == width)
		{
			sigrec = new Rectangle(datarec.GetX(), datarec.GetY() - height - 30, width, height);
		}
		else if (datarec.GetWidth() > width)
		{
			sigrec = new Rectangle(
				datarec.GetX() + ((datarec.GetWidth() - width) / 2),
				datarec.GetY() - height - 30, width, height
				);
		}
		PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
		.SetReason("A")
		.SetLocation("B")
		.SetReuseAppearance(false)
		.SetPageRect(sigrec)
		.SetPageNumber(signer.GetDocument().GetNumberOfPages())
		.SetCertificate(certBag.Certificate)
		.SetLayer2Text("");
		PdfFont font = PdfFontFactory.CreateFont(@"C:\Windows\Fonts\times.ttf", "cp1251", iText.Kernel.Font.PdfFontFactory.EmbeddingStrategy.PREFER_EMBEDDED, true);
		Table table = new Table(2).SetWidth(width).SetHeight(height).SetFixedLayout().SetFixedPosition(sigrec!.GetX(), datarec.GetY() - height - 30f, width).SetMargin(0).SetPadding(0);
		Cell LogoCell = new Cell().SetBorder(Border.NO_BORDER);
		LogoCell.SetWidth(50f).SetHeight(40f).SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE).SetHorizontalAlignment(HorizontalAlignment.CENTER);
		LogoCell.Add(
			new Image(ImageDataFactory.Create("1.jpg")).SetAutoScale(true).SetHorizontalAlignment(HorizontalAlignment.RIGHT)
			).SetPadding(0);

		Cell IsSigned = new Cell().SetBorder(Border.NO_BORDER);
		IsSigned.SetWidth(width-50f).SetHeight(40f).SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE);
		IsSigned.Add(
			new Paragraph("документ подписан\nэлектронной подписью".ToUpper())
				.SetFontColor(ColorConstants.BLUE)
				.SetFontSize(7f)
				.SetTextAlignment(iText.Layout.Properties.TextAlignment.CENTER)
				.SetFont(font).SetMarginRight(40)
			);
		Cell CertCell = new Cell(1, 2).SetBorder(Border.NO_BORDER);
		CertCell.SetHeight(40f).SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE);
		CertCell.Add(
			new Paragraph("Сертификат: " + $"{BitConverter.ToString(certBag.Certificate.SerialNumber.ToByteArray()).Replace("-", "").ToLower()}".ToLower())
				.SetFontColor(ColorConstants.BLUE)
				.SetFontSize(7f)
				.SetTextAlignment(iText.Layout.Properties.TextAlignment.LEFT)
				.SetFont(font).SetPadding(0)
			);
		CertCell.Add(
			new Paragraph($"Владелец: {certBag.Certificate.SubjectDN.GetValueList(new DerObjectIdentifier("2.5.4.3"))[0]}")
				.SetFontColor(ColorConstants.BLUE)
				.SetFontSize(7f)
				.SetTextAlignment(iText.Layout.Properties.TextAlignment.LEFT)
				.SetFont(font).SetPadding(0)
			);
		CertCell.Add(
			new Paragraph($"Действителен с {certBag.Certificate.NotBefore.Date.ToString("d")} по {certBag.Certificate.NotAfter.Date.ToString("d")}")
				.SetFontColor(ColorConstants.BLUE)
				.SetFontSize(7f)
				.SetTextAlignment(iText.Layout.Properties.TextAlignment.LEFT)
				.SetFont(font).SetPadding(0)
			);
		table.AddCell(LogoCell);
		table.AddCell(IsSigned);
		table.AddFooterCell(CertCell);
		Document doc = new Document(signer.GetDocument());
		PdfCanvas pdfCanvas0 = new PdfCanvas(appearance.GetLayer2(), signer.GetDocument())
			.SetFontAndSize(font, 34f)
			.SetLineWidth(2)
			.SetStrokeColor(iText.Kernel.Colors.ColorConstants.BLUE).SetFillColor(ColorConstants.WHITE)
			.RoundRectangle(0, 0, sigrec!.GetWidth(), sigrec.GetHeight(), 8)
			.Stroke();
		doc.Add(table);
		iText.Signatures.IExternalSignature pks = new iText.Signatures.PrivateKeySignature(prkBag.Key, publickeyparams.DigestParamSet.Id);
		signer.SignDetached(pks, new X509Certificate[] { certBag.Certificate }, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
		Console.WriteLine("PDF is signed!");
		reader.Close();
		writer.Close();
	}
	catch
	{
		Console.WriteLine("PDF is NOT signed!");
	}
}

static void Sample_16_VerifyPAdES(string _PAdES_SigFileName)
{
	Console.WriteLine("\nSample_16_VerifyPAdES");
	iText.Kernel.Pdf.PdfReader reader = new iText.Kernel.Pdf.PdfReader(_PAdES_SigFileName);
	iText.Kernel.Pdf.PdfDocument doc = new iText.Kernel.Pdf.PdfDocument(reader);
	SignatureUtil util = new SignatureUtil(doc);
	try
	{
		iText.Signatures.PdfPKCS7 sig = util.ReadSignatureData("Signature1");
		if (sig != null)
		{
			var flag = sig.VerifySignatureIntegrityAndAuthenticity();
			Console.WriteLine($"Signature verification status: {flag}");
		}
	}
	catch
	{
		Console.WriteLine("Signature NOT verified!");
	}
}

static void WritePemObject(Object _object, String _fileName)
{
	TextWriter TextWriter = File.CreateText($".\\{_fileName}");
	var PemWriter = new PemWriter(TextWriter);
	PemWriter.WriteObject(_object);
	TextWriter.Flush();
	TextWriter.Close();
	TextWriter.Dispose();
}

static System.Object ReadPemObject(String _fileName)
{
	TextReader TextReader = File.OpenText($".\\{_fileName}");
	var PemReader = new PemReader(TextReader);
	var _object = PemReader.ReadObject();
	TextReader.Close();
	TextReader.Dispose();
	return _object;
}
