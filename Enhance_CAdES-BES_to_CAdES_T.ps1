Add-Type -Path ".\BouncyCastle.Cryptography.dll"

& "C:\Program Files\Crypto Pro\CSP\cryptcp.exe" -sign -cadesbes -attached -addchain -cert -thumb 0bf066220c8d1add753aead9e17c11208f5bbb56 .\tsb.txt .\tsb.txt.sig -der

$TspURL = "http://testca2012.cryptopro.ru/tsp/tsp.srf"

$cades_signature = [Org.BouncyCastle.Cms.CmsSignedData]::new((Get-Content -AsByteStream:$true -Path:".\tsb.txt.sig"))

$signer_cert_dict = [System.Collections.Generic.List[Org.BouncyCastle.Cms.SignerInformation]]::new()

$certList = [System.Collections.Generic.List[Org.BouncyCastle.X509.X509Certificate]]::new()

$m = [System.IO.MemoryStream]::new()

$fileBytes = $null

if ($null -ne $cades_signature.SignedContent) {
    $cades_signature.SignedContent.Write($m);
    $fileBytes = $m.ToArray()
}
else {
    $fileBytes = [byte[]]::new(0)
}

0..($cades_signature.GetSignerInfos().GetSigners().Count-1) | ForEach-Object {
    $signer = $cades_signature.GetSignerInfos().GetSigners()[$_]

    $signerCert = $cades_signature.GetCertificates().EnumerateMatches($signer.SignerID)[0]

    $signerPubKey = $signerCert.GetPublicKey();

    $publicKeyParams = $signerPubKey.Parameters

    $tspReqGenerator = [Org.BouncyCastle.Tsp.TimeStampRequestGenerator]::new()

    $tspReqGenerator.SetCertReq($true);

    $tspReq = $tspReqGenerator.Generate(
        $publicKeyParams.DigestParamSet.Id,
        [Org.BouncyCastle.Security.DigestUtilities]::CalculateDigest($publicKeyParams.DigestParamSet.Id, $signer.GetSignature()),
        [Org.BouncyCastle.Math.BigInteger]::Zero
    )

    $encodedTspRequest = $tspReq.GetEncoded()

    $httpResponse = (Invoke-WebRequest -Uri $TspURL -Method:Post -ContentType:"application/timestamp-query" -Body:$encodedTspRequest).Content

    $tspResponse = [Org.BouncyCastle.Tsp.TimeStampResponse]::new($httpResponse)

    $timeStampToken = [Org.BouncyCastle.Asn1.DerSequence]::FromByteArray($tspResponse.TimeStampToken.ToCmsSignedData().GetEncoded())

    $timeStampTokenAttr = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers]::IdAASignatureTimeStampToken,
        [Org.BouncyCastle.Asn1.DerSet]::new($timeStampToken)
    )

    $unsignedAttrsTable = [Org.BouncyCastle.Asn1.Cms.AttributeTable]::new(
        [Org.BouncyCastle.Asn1.Cms.Attributes]::new(
            [Org.BouncyCastle.Asn1.Asn1EncodableVector]::new(
                $timeStampTokenAttr.ToAsn1Object()
            )
        )
    )

    $signer = [Org.BouncyCastle.Cms.SignerInformation]::ReplaceUnsignedAttributes($signer[0], $unsignedAttrsTable)

    $signer_cert_dict.Add($signer)

    $certList.Add(($cades_signature.GetCertificates().EnumerateMatches($signer.SignerID) -as [System.Collections.Generic.List[Org.BouncyCastle.X509.X509Certificate]])[0])
}

$newcmssigndata = [Org.BouncyCastle.Cms.CmsSignedDataGenerator]::new()

$newcmssigndata.UseDerForCerts = $true

$signer_cert_dict | ForEach-Object {
    $newcmssigndata.AddSigners(
        [Org.BouncyCastle.Cms.SignerInformationStore]::new(
            $_
        )
    )
}

$certStore = [Org.BouncyCastle.Utilities.Collections.CollectionUtilities]::CreateStore($certList)

$newcmssigndata.AddCertificates($certStore)

$message = [Org.BouncyCastle.Cms.CmsProcessableByteArray]::new($fileBytes)

$CAdES_T = $null

if ($null -ne $cades_signature.SignedContent) {
    $CAdES_T = $newcmssigndata.Generate($message, $true)
}
else {
    CAdES_T = $newcmssigndata.Generate($message, $false)
}

Set-Content -AsByteStream:$true -Path:".\tsb.txt.cadest.sig" -Value:($CAdES_T.GetEncoded())
