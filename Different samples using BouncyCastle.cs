//.Net 6.0
//.Net Assemblies
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Collections;

//BouncyCastle v 1.9.0
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

//ASN1.Reader
using Net.Asn1.Reader;

//Itext.Sharp
using iTextSharp.text.io;
using iTextSharp.text.pdf;

var PrKeyFileName = "prk.pem";
var PbKeyFileName = "pbk.pem";
var ToBeSigned = "Hello, world!";
var ToBeSignedFileName = "toBeSigned.txt";
File.WriteAllBytes(ToBeSignedFileName, Encoding.ASCII.GetBytes(ToBeSigned));
var RawSigFileName = "toBeSignedRaw.sig";
var CertRequestFileName = "req.req";
var SelfSignedCertFileName = "cert.crt";
var PFXFileName = "pfx.pfx";
var PFXPass = "12345qwerty";
var CAdES_BES_SigFileName = "toBeSignedCAdES_BES.sig";
var IssuedCertFileName = "issued_cert.crt";
var Header_Key_FileName = "header.key";
var CrlFileName = "crl.crl";
var PdfFileName = "1.pdf";

Sample_1_Generate_Gost3410_2012_KeyPair(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_2_Read_Gost3410_2012_KeyPair_FromFile(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_3_Sign_And_Export_RawSignature_ToFile (PrKeyFileName, PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_4_ImportandVerify_RawSignature(PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_5_GenerateCertRequest(PrKeyFileName, PbKeyFileName, CertRequestFileName);
Sample_6_GenerateSelfSignedCertificate(PrKeyFileName, PbKeyFileName, SelfSignedCertFileName);
Sample_7_ExportPfx(PrKeyFileName, PFXFileName, SelfSignedCertFileName, PFXPass);
Sample_8_ImportPfx(PFXFileName, PFXPass);
Sample_9_SignCertRequest(PFXFileName, PFXPass, CertRequestFileName, IssuedCertFileName);
Sample_10_Create_Attached_CAdES_BES(PFXFileName, PFXPass, CAdES_BES_SigFileName, ToBeSignedFileName);
Sample_11_Verify_Attached_CAdES_BES(CAdES_BES_SigFileName);
//Sample_12_BuildCertChain
Sample_13_SignCRL(CrlFileName);
//Sample_14_CreateOCSPResponse
Sample_15_ExportCertsFromCryptoProContainer(Header_Key_FileName);
Sample_16_VerifyPAdES(PdfFileName);

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

static void Sample_3_Sign_And_Export_RawSignature_ToFile (string _PrKeyFileName, string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
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
	var signatureBytes = File.ReadAllBytes(_RawSigFileName);
	ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
	Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(signatureBytes[0..32]);
	Org.BouncyCastle.Math.BigInteger s = new Org.BouncyCastle.Math.BigInteger(signatureBytes[32..64]);
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

static void Sample_5_GenerateCertRequest (string _PrKeyFileName, string _PbKeyFileName, string _CertRequestFileName)
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
		new X509Name("CN=Anatolka, L=Moscow"),
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
	certGen.SetIssuerDN(new X509Name("CN=Anatolka"));
	certGen.SetNotBefore(DateTime.UtcNow);
	certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
	certGen.SetPublicKey(pbk);
	certGen.SetSubjectDN(new X509Name("CN=Anatolka"));

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

static void Sample_7_ExportPfx (string _PrKeyFileName, string _PFXFileName, string _CertFileName, string _PFXPass)
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

static void Sample_9_SignCertRequest (string _PFXFileName, string _PFXPass, string _CertRequestFileName, string _IssuedCertFileName)
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

static void Sample_12_BuildCertChain()
{
	//TODO
}

static void Sample_13_SignCRL(string _CrlFileName)
{
	Console.WriteLine("\nSample_13_SignCRL");
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

static void Sample_14_CreateOCSPResponse()
{
	//TODO
}

static void Sample_15_ExportCertsFromCryptoProContainer (string _Header_Key_FileName)
{
	var b = File.ReadAllBytes(_Header_Key_FileName);
	var m = new MemoryStream(b);
	var berReader = new BerReader(m);
	var header_key = berReader.ReadToEnd(true);
	var potentialCertStore = header_key.ChildNodes[0].ChildNodes[0];
	List<Org.BouncyCastle.X509.X509Certificate> certStore = new List<Org.BouncyCastle.X509.X509Certificate>();
	var e = potentialCertStore.ChildNodes.GetEnumerator();
	while (e.MoveNext())
    	{
		var tempCertRawBytes = e.Current.RawValue;
		try
        	{
			Org.BouncyCastle.X509.X509Certificate tempCert = new Org.BouncyCastle.X509.X509Certificate(tempCertRawBytes);
			certStore.Add(tempCert);
		}
		catch
        	{
			//TODO
		}
    	}
	switch (certStore.Count > 0)
    	{
		case false: {
				Console.WriteLine("No certs found!");
				break;
            	}
    	}
}

static void Sample_16_VerifyPAdESUsingOldITextSharpAPI (string _PdfFileName) 
{
	if (args.Length < 1)
            {
                Console.WriteLine("Pdf.Verify <document>");
                
            }
            string document = _PdfFileName;

            PdfReader reader = new PdfReader(document);

            AcroFields af = reader.AcroFields;
            List<string> names = af.GetSignatureNames();
            foreach (string name in names)
            {
                string message = "Signature name: " + name;
                message += "\nSignature covers whole document: " + af.SignatureCoversWholeDocument(name);
                message += "\nDocument revision: " + af.GetRevision(name) + " of " + af.TotalRevisions;

                PdfDictionary singleSignature = af.GetSignatureDictionary(name);
                PdfString asString1 = singleSignature.GetAsString(PdfName.CONTENTS);
                byte[] signatureBytes = asString1.GetOriginalBytes();

                RandomAccessFileOrArray safeFile = reader.SafeFile;

                PdfArray asArray = singleSignature.GetAsArray(PdfName.BYTERANGE);
                using (
                    Stream stream =
                        (Stream)
                        new RASInputStream(
                            new RandomAccessSourceFactory().CreateRanged(
                                safeFile.CreateSourceView(),
                                (IList<long>)asArray.AsLongArray())))
                {
                    using (MemoryStream ms = new MemoryStream((int)stream.Length))
                    {
                        stream.CopyTo(ms);
                        byte[] data = ms.GetBuffer();

                        var ContentInfo = new CmsProcessableByteArray(data);
                        var CmsSignedData = new CmsSignedData(ContentInfo, signatureBytes);


                        var certStoreInSig = CmsSignedData.GetCertificates("collection");
                        var sgnrs = CmsSignedData.GetSignerInfos().GetSigners();
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
                                Console.WriteLine($"PAdES verification status: {reslt}");
                                var encodedSignedAttributes = sgnr.GetEncodedSignedAttributes();
                                var sig = sgnr.GetSignature();
                                var publicKey = (ECPublicKeyParameters)cert.GetPublicKey();
                                var publicKeyParams = (ECGost3410Parameters)publicKey.Parameters;
                                var encodedSignedAttributesHash = DigestUtilities.CalculateDigest(publicKeyParams.DigestParamSet.Id, (byte[])ContentInfo.GetContent());
                                var r = new Org.BouncyCastle.Math.BigInteger(1, sig, 32, 32);
                                var s = new Org.BouncyCastle.Math.BigInteger(1, sig, 0, 32);
                                var gostVerifier = new ECGost3410Signer();
                                gostVerifier.Init(false, publicKey);
                                Console.WriteLine($"Manual PAdES verification status: {gostVerifier.VerifySignature(encodedSignedAttributesHash, r, s)}");
                            }
                        }
                        Console.ReadKey();
                    }
                }
            }
}

static void Sample_17_VerifyUsingNewITextSharpAPI(string _fileName) 
{
	Console.WriteLine($"Verify {_fileName} using new ITextSharp interface");
	iText.Kernel.Pdf.PdfReader reader = new iText.Kernel.Pdf.PdfReader(_fileName);
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

         }
}

static void Sample_18_SignUsingNewITextSharpAPI(string _fileName, string _pfxFileName, string _pfxPass) 
{
	var pfxBytes = File.ReadAllBytes(_pfxPath);
        var builder = new Pkcs12StoreBuilder();
        builder.SetUseDerEncoding(false);
        var store = builder.Build();
        var m = new MemoryStream(pfxBytes);
        store.Load(m, _pfxPass.ToCharArray());
        m.Close();
        AsymmetricKeyEntry prkBag = store.GetKey("prk");
        X509CertificateEntry certBag = store.GetCertificate("cert");
        var publicKey = (ECPublicKeyParameters)certBag.Certificate.GetPublicKey();
        var publickeyparams = (ECGost3410Parameters)publicKey.Parameters;

	PdfReader reader = new PdfReader(PdfFileName);
	PdfDocument p = new PdfDocument(reader);
	reader = new PdfReader(PdfFileName);
	PdfWriter writer = new PdfWriter(new FileStream($"{PdfFileName}.temp", FileMode.Create, FileAccess.ReadWrite), new WriterProperties().SetFullCompressionMode(false)); //решаем проблему со сжатием при наличии в файле Cross-Reference Streams
	PdfDocument toBeSaved = new PdfDocument(reader, writer);
	toBeSaved.Close();
	writer.Close();
	reader.Close();
	reader = new PdfReader($"{PdfFileName}.temp");
	PdfDocumentContentParser pcp = new iText.Kernel.Pdf.Canvas.Parser.PdfDocumentContentParser(p);
	TextMarginFinder finder = pcp.ProcessContent(p.GetNumberOfPages(), new iText.Kernel.Pdf.Canvas.Parser.Listener.TextMarginFinder());
	Rectangle datarec = finder.GetTextRectangle();
	PdfSigner signer = new PdfSigner(reader, new FileStream($"{PdfFileName}.signed.pdf", FileMode.OpenOrCreate, FileAccess.ReadWrite), new StampingProperties().UseAppendMode());
	signer.SetFieldName("Signature1");
	Rectangle sigrec = new Rectangle(datarec.GetX() + datarec.GetWidth() / 2, datarec.GetY() - 100, 200, 100);
	PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
	.SetReason("A")
	.SetLocation("B")
	.SetReuseAppearance(false)
	.SetPageRect(sigrec)
	.SetPageNumber(p.GetNumberOfPages())
	.SetCertificate(certBag.Certificate);
	appearance.SetLayer2Font(iText.Kernel.Font.PdfFontFactory.CreateFont(iText.IO.Font.Constants.StandardFonts.TIMES_ROMAN));
        iText.Signatures.IExternalSignature pks = new iText.Signatures.PrivateKeySignature(prkBag.Key, publickeyparams.DigestParamSet.Id);
        signer.SignDetached(pks, new X509Certificate[] { certBag.Certificate }, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
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
