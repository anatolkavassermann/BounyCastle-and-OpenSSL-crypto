using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Collections;

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


//Sample_1_Generate_Gost3410_2012_KeyPair("prk.pem", "pbk.pem", "0.cer");
//Sample_5_GenerateCertRequest("prk.pem", "pbk.pem", "req1.req");
//Sample_7_ExportPfx("prk.pem", "pfx.pfx", "1.cer", "12345");
CreateCMC("pfx.pfx", "12345", "cmc.req", "req1.req");

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
	extGen.AddExtension(new DerObjectIdentifier("1.2.643.100.114"), false, new DerInteger(0));
	AttributePkcs attributePkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
	List<DerObjectIdentifier> oids = new List<DerObjectIdentifier>();
	List<string> values = new List<string>();
	oids.Add(new DerObjectIdentifier("2.5.4.3"));
	oids.Add(new DerObjectIdentifier("1.2.643.100.3"));
	oids.Add(new DerObjectIdentifier("1.2.643.3.131.1.1"));
	values.Add("Тестерович Тестер BC");
	values.Add("00000000000");
	values.Add("000000000000");
	var request = new Pkcs10CertificationRequest(
		"1.2.643.7.1.1.3.2",
		(new X509Certificate(File.ReadAllBytes("0.cer"))).SubjectDN,
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

static void Sample_7_ExportPfx(string _PrKeyFileName, string _PFXFileName, string _CertFileName, string _PFXPass)
{
	Console.WriteLine("\nSample_7_ExportPfx");
	var secureRandom = new SecureRandom();
	ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
	X509Certificate x509 = new X509Certificate(File.ReadAllBytes(_CertFileName));
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

static void CreateCMC(string _PFXFileName, string _PFXPass, string _CAdES_BES_SigFileName, string _ToBeSignedFileName)
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
	var fileBytes = ((Pkcs10CertificationRequest)ReadPemObject(_ToBeSignedFileName));
	DerSequence req = new DerSequence(
		new Asn1Encodable[]
		{
					//new DerSequence(),
					new DerSequence (
						new Asn1Encodable[]
						{
							new DerTaggedObject(
								false,
								0,
								new DerSequence(
									new Asn1Encodable[]
									{
										new DerInteger(0),
										fileBytes
									}
								)
							)
						}

					),
			//new DerSequence(),
			//new DerSequence()
		}
	);
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
	var fileHash = DigestUtilities.CalculateDigest(publicKeyParams.DigestParamSet, fileBytes.GetDerEncoded());
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
	var message = new CmsProcessableByteArray(fileBytes.GetDerEncoded());

	//var attachedCAdESBES = gen.Generate("1.3.6.1.5.5.7.12.2", message, true);
	var attachedCAdESBES = gen.Generate(message, true);
	var e = attachedCAdESBES.GetSignerInfos().GetSigners().GetEnumerator();
	while (e.MoveNext())
	{
		SignerInformation s = (SignerInformation)e.Current;
	}
	var encodedSignedData = attachedCAdESBES.GetEncoded("DER");
	var convertedSignedData = Convert.ToBase64String(encodedSignedData);
	File.WriteAllBytes(_CAdES_BES_SigFileName, Encoding.ASCII.GetBytes(convertedSignedData));
	Console.WriteLine("CMC generated");
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
