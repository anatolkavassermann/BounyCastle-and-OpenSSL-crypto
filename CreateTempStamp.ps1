#Для тестов буду юзать криптографическую либу BouncyCastle. Для парсинга PDF - itext7
gci -Filter *.dll | % {Add-Type -Path $_} #Подгружаем либы itext7 и BouncyCastle
function Sign-PDF {
    [void]([Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder]::new() | % { #Разбор pfx 
        $_.SetUseDerEncoding($true); 
        $store = $_.Build();
        $m = [System.IO.MemoryStream]::new([System.IO.File]::ReadAllBytes((gi -Path ".\pfx.pfx"))) 
        $store.Load(
            $m,
            "12345qwerty".ToCharArray()
        );
        $m.Close()
        $prkBag = $store.GetKey("prk"); 
        $certBag = $store.GetCertificate("cert"); 
        $publicKeyParams = $certBag.Certificate.GetPublicKey().Parameters;
    })
    $fileBytes = [System.IO.File]::ReadAllBytes((gi -Path ".\orig_PDFtoBeSigned.pdf"))
    $certList = [System.Collections.Generic.List[Org.BouncyCastle.X509.X509Certificate]]::new()
    $certList.Add($certBag.Certificate)
    $storeParams = [Org.BouncyCastle.X509.Store.X509CollectionStoreParameters]::new($certList)
    $certStore = [Org.BouncyCastle.X509.Store.X509StoreFactory]::Create("Certificate/Collection", $storeParams)
    $certHash = [Org.BouncyCastle.Security.DigestUtilities]::CalculateDigest($publicKeyParams.DigestParamSet.Id, $certBag.Certificate.GetEncoded())
    $essV2Cert = [Org.BouncyCastle.Asn1.Ess.EssCertIDv2]::new(
        [Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier]::new(
            $publicKeyParams.DigestParamSet.Id
        ),
        $certHash,
        [Org.BouncyCastle.Asn1.X509.IssuerSerial]::new(
            [Org.BouncyCastle.Asn1.X509.GeneralNames]::new(
                [Org.BouncyCastle.Asn1.X509.GeneralName]::new(
                    $certBag.Certificate.IssuerDN
                )
            ),
            [Org.BouncyCastle.Asn1.DerInteger]::new($certBag.Certificate.SerialNumber)
        )
    )   
    $signingCertV2 = [Org.BouncyCastle.Asn1.Ess.SigningCertificateV2]::new(@($essV2Cert) -as [Org.BouncyCastle.Asn1.Ess.EssCertIDv2[]])
    $fileHash =[Org.BouncyCastle.Security.DigestUtilities]::CalculateDigest($publicKeyParams.DigestParamSet.Id, $fileBytes)
    $essattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers]::IdAASigningCertificateV2,
        [Org.BouncyCastle.Asn1.DerSet]::new($signingCertV2)
    )
    $ctattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Cms.CmsAttributes]::ContentType,
        [Org.BouncyCastle.Asn1.DerSet]::new(
            [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.2.840.113549.1.7.1")
        )
    )
    $mdattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Cms.CmsAttributes]::MessageDigest,
        [Org.BouncyCastle.Asn1.DerSet]::new(
            [Org.BouncyCastle.Asn1.DerOctetString]::new($fileHash)
        )
    )
    $signedAttrs = [hashtable]::new()
    $signedAttrs.Add($essattb.AttrType, $essattb)
    $signedAttrs.Add($ctattb.AttrType, $ctattb)
    $signedAttrs.Add($mdattb.AttrType, $mdattb)
    $signedAttributesTable = [Org.BouncyCastle.Asn1.Cms.AttributeTable]::new($signedAttrs)
    $signedAttributeGenerator = [Org.BouncyCastle.Cms.DefaultSignedAttributeTableGenerator]::new(
        $signedAttributesTable
    )
    [Org.BouncyCastle.Cms.CmsSignedDataGenerator]::new() | % {
        $_.UseDerForCerts = $true;
        $_.AddCertificates($certStore);
        $_.AddSigner(
            $prkBag.Key,
            $certBag.Certificate,
            $publicKeyParams.DigestParamSet.Id,
            $signedAttributeGenerator,
            $null
        )
        $message = 
        $attachedCAdESBES = $_.Generate(
            [Org.BouncyCastle.Cms.CmsProcessableByteArray]::new($fileBytes),
            $false
        )
        $encodedSignedData = $attachedCAdESBES.GetEncoded("DER");
        [System.IO.File]::WriteAllBytes(".\CAdES_BES_Detached.sig", $encodedSignedData)
    }
}
function Create-TempPdf {
    $verificationResult = $false
    $signedContent = [Org.BouncyCastle.Cms.CmsProcessableByteArray]::new([System.IO.File]::ReadAllBytes((gi ".\orig_PDFtoBeSigned.pdf")))
    $signatureBytes = [System.IO.File]::ReadAllBytes((gi ".\CAdES_BES_Detached.sig"))
    $cmsSignedData = [Org.BouncyCastle.Cms.CmsSignedData]::new($signedContent, $signatureBytes)
    $certStoreInSig = $cmsSignedData.GetCertificates("collection");
    $signers = $cmsSignedData.GetSignerInfos().GetSigners();
    $signers | % {
        $cert = $certStoreInSig.GetMatches($_.SignerID)[0];
        $verificationResult = $_.Verify($cert)
    }
    if ($verificationResult) {
        $reader = [iText.Kernel.Pdf.PdfReader]::new((gi -Path ".\orig_PDFtoBeSigned.pdf"));
        [iText.Kernel.Pdf.PdfWriter] $writer = [iText.Kernel.Pdf.PdfWriter]::new(
            [System.IO.FileStream]::new(
                ".\orig_PDFtoBeSigned.signed.pdf",
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::ReadWrite
            ),
            [iText.Kernel.Pdf.WriterProperties]::new().SetFullCompressionMode($false)
        )
        $p = [iText.Kernel.Pdf.PdfDocument]::new($reader, $writer)
        $pcp = [iText.Kernel.Pdf.Canvas.Parser.PdfDocumentContentParser]::new($p)
        $finder = $pcp.ProcessContent(
            $p.GetNumberOfPages(),
            [iText.Kernel.Pdf.Canvas.Parser.Listener.TextMarginFinder]::new()
        )
        $datarec = $finder.GetTextRectangle()
        $width = 300
        $height = 100
        if ($datarec.GetWidth() -lt $width) {
            $sigrec = [iText.Kernel.Geom.Rectangle]::new(
                $datarec.GetX() - (($width - $datarec.GetWidth()) / 2),
                $datarec.GetY() - $height - 30, $width, $height
            )
        }
        elseif ($datarec.GetWidth() -eq $width) {
            $sigrec = [iText.Kernel.Geom.Rectangle]::new(
                $datarec.GetX(), 
                $datarec.GetY() - $height - 30, $width, $height
            )
        }
        elseif ($datarec.GetWidth() -gt $width) {
            $sigrec = [iText.Kernel.Geom.Rectangle]::new(
                $datarec.GetX() + (($datarec.GetWidth() - $width) / 2),
                $datarec.GetY() - $height - 30, $width, $height
            );
        }
        $font = [iText.Kernel.Font.PdfFontFactory]::CreateFont("C:\Windows\Fonts\times.ttf", "cp1251", [iText.Kernel.Font.PdfFontFactory+EmbeddingStrategy]::PREFER_EMBEDDED, $true)
        $par1 = [iText.Layout.Element.Paragraph]::new("ДОКУМЕНТ ПОДПИСАН ЭЛЕКТРОННОЙ ПОДПИСЬЮ")
        $par1.SetFont($font)
        $par1.SetFontSize(10)
        $par1.SetFontColor([iText.Kernel.Colors.ColorConstants]::BLUE)
        $par1.SetTextAlignment([iText.Layout.Properties.TextAlignment]::CENTER)
        $builder = [System.Text.StringBuilder]::new()
        
        $builder.AppendLine("Сертификат: $([System.BitConverter]::ToString(
                $cert.SerialNumber.ToByteArray()).Replace("-",`"`").ToLower()
            )"
        );
        $builder.AppendLine("Владелец: $(
            $cert.SubjectDN.GetValueList(
                [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("2.5.4.3")
            )[0]
        )");
        $builder.AppendLine("Действителен с $(
            $cert.NotBefore.Date.ToString("d")
        ) по $(
            $cert.NotAfter.Date.ToString("d")
        )");
        $par2 = [iText.Layout.Element.Paragraph]::new($builder.ToString())
        $par2.SetFont($font)
        $par2.SetFontSize(10)
        $par2.SetFontColor([iText.Kernel.Colors.ColorConstants]::BLUE)
        $par2.SetTextAlignment([iText.Layout.Properties.TextAlignment]::CENTER)
        $PdfCanvas = [iText.Kernel.Pdf.Canvas.PdfCanvas]::new($p.GetLastPage())
        $PdfCanvas.SetStrokeColor([iText.Kernel.Colors.ColorConstants]::BLUE)
        $PdfCanvas.RoundRectangle($sigrec.GetX(), $sigrec.GetY(), $sigrec.GetWidth(), $sigrec.GetHeight(), 10)
        $PdfCanvas.Stroke()
        $Canvas = [iText.Layout.Canvas]::new(
            $PdfCanvas, $sigrec
        )
        $Canvas.Add(
            [iText.Layout.Element.Div]::new(
    
            ).SetHeight($sigrec.GetHeight()).SetWidth($sigrec.GetWidth()).SetVerticalAlignment([iText.Layout.Properties.VerticalAlignment]::MIDDLE).SetMarginLeft(10).SetMarginRight(10).Add($par1).Add($par2)
        )
        $Canvas.Close()
        $p.Close()
        $reader.Close()
        $writer.Close()
        & "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe" ".\orig_PDFtoBeSigned.signed.pdf"
    }
}
Sign-PDF
Create-TempPdf
