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

//ASN1 Reader
using Net.Asn1.Reader;

static void Sample_15_ExportCerts_FromContainer ()
{
	var b = File.ReadAllBytes(@"E:\OLD\OLDOLDO\OSSO4GB\Very\Very OLD\OOLLDD\OLD\Old_Old\23.000\header.key");
	var m = new MemoryStream(b);
	var berReader = new BerReader(m);
	var header_key = berReader.ReadToEnd(true);
	var potentialCertStore = header_key.ChildNodes[0].ChildNodes[0];
	List<Org.BouncyCastle.X509.X509Certificate> certStore = new List<X509Certificate>();
	var e = potentialCertStore.ChildNodes.GetEnumerator();
	while (e.MoveNext())
    {
		var tempCertRawBytes = e.Current.RawValue;
		try
        {
			Org.BouncyCastle.X509.X509Certificate tempCert = new X509Certificate(tempCertRawBytes);
			certStore.Add(tempCert);
		}
		catch
        {
		}
    }
}
