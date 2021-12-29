//.Net 6.0
//.Net Assemblies
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Collections;

//BouncyCastle v. 1.9.0
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

Sample_1_Generate_Gost3410_2012_KeyPair(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_2_Read_Gost3410_2012_KeyPair_FromFile(PrKeyFileName, PbKeyFileName, ToBeSigned);
Sample_3_Export_RawSignature_ToFile(PrKeyFileName, PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_4_ImportandVerify_RawSignature(PbKeyFileName, RawSigFileName, ToBeSignedFileName);
Sample_5_GenerateCertRequest(PrKeyFileName, PbKeyFileName, CertRequestFileName);
Sample_6_GenerateSelfSignedCertificate(PrKeyFileName, PbKeyFileName, SelfSignedCertFileName);
Sample_7_ExportPfx(PrKeyFileName, PFXFileName, SelfSignedCertFileName, PFXPass);
Sample_8_ImportPfx(PFXFileName, PFXPass);

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

static void Sample_3_Export_RawSignature_ToFile(string _PrKeyFileName, string _PbKeyFileName, string _RawSigFileName, string _ToBeSignedFileName)
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

static void Sample_9_SignCertRequest ()
{
	//TODO
}

static void Sample_10_Create_CAdES_BES()
{
	//TODO
}

static void Sample_11_Verify_CAdES_BES()
{
	//TODO
}

static void Sample_12_BuildCertChain()
{
	//TODO
}

static void Sample_13_SignCRL()
{
	//TODO
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
