//.Net Assemblies
using System;
using System.Text;
using System.IO;

//BouncyCastle v 1.9.0
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

var PrKeyFileName = "prk.pem";
var PbKeyFileName = "pbk.pem";
var ToBeSigned = "Hello, world!";

Generate_Gost3410_2012_KeyPair(PrKeyFileName, PbKeyFileName, ToBeSigned);
static void Generate_Gost3410_2012_KeyPair(string _PrKeyFileName, string _PbKeyFileName, string _ToBeSigned) {
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
				break;
			}
		default:
            {
				Console.WriteLine("Key pair not generated!");
				break;
            }
	}
}

static void WritePemObject (Object _object, String _fileName)
{
	TextWriter TextWriter = File.CreateText($".\\{_fileName}");
	var PemWriter = new PemWriter(TextWriter);
	PemWriter.WriteObject(_object);
	TextWriter.Flush();
	TextWriter.Close();
	TextWriter.Dispose();
}

static System.Object ReadPemObject (String _fileName)
{
	TextReader TextReader = File.OpenText($".\\{_fileName}");
	var PemReader = new PemReader(TextReader);
	var _object = PemReader.ReadObject();
	TextReader.Close();
	TextReader.Dispose();
	return _object;
}