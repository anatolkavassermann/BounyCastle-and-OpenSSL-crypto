#openssl pkcs12 -engine gost -export -inkey prk.pem -in crt.pem -out pfx.pfx -password pass:123 -keypbe gost89 -certpbe gost89 -macalg md_gost12_256 Сохраню это тут
#p12util.x86.exe -p12tocp -rdrfolder .\123 -contname mycont -ex -passp12 123 -infile .\pfx.pfx -noMACVerify -noCPKM

function Sample_1_Generate_Gost3410_2012_KeyPair {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $PbKFilePath = "pbk.pem"
    )

    openssl genpkey -outform PEM -algorithm gost2012_256 -pkeyopt paramset:TCA -out $PrKFilePath
    #не знаю, как иначе получить открытый ключ. Используя команду "openssl genpkey" можно получить открытый ключ, но он будет представлен в виде координат
    #I don't know how else to get the private key. you can get the public key using the command "openssl genpkey" , but it will be represented as a coordinates
    openssl req -new -key $PrKFilePath -subj "/" -noout -pubkey -outform PEM -out $PbKFilePath 
}

function Sample_3_Sign_And_Export_RawSignature_ToFile {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $ToBeSignedFilePath = "to_be_signed.txt",
        [parameter(Mandatory=$false)] [System.String] $RAWSigFilePath = "to_be_signed.txt.sig"
    )

    openssl dgst -sign $PrKFilePath -md_gost12_256 -binary -out $RAWSigFilePath $ToBeSignedFilePath
}

function Sample_4_Verify_RawSignature_ToFile {
    param (
        [parameter(Mandatory=$false)] [System.String] $PbKFilePath = "pbk.pem",
        [parameter(Mandatory=$false)] [System.String] $ToBeSignedFilePath = "to_be_signed.txt",
        [parameter(Mandatory=$false)] [System.String] $RAWSigFilePath = "to_be_signed.txt.sig"
    )

    $ans = openssl dgst -verify $PbKFilePath -md_gost12_256 -signature $RAWSigFilePath $ToBeSignedFilePath
    switch ($ans) {
        "Verified OK" {
            Write-Host -ForegroundColor Green -Object "Signature Verified"
        }

        default {
            Write-Host -ForegroundColor Red -Object "Signature NOT Verified"
        }
    }
}

function Sample_5_GenerateCertRequest {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $CertReqFilePath = "req.req"
    )
    
    openssl req -new -key $PrKFilePath -subj "/CN=Anatolka/L=Moscow" -outform PEM -out $CertReqFilePath
    openssl req -key prk.pem -outform PEM -subj "/CN=Anatolka/L=Moscow" -addext extendedKeyUsage=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4 -addext keyUsage=critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement -new -outform PEM -out req.req
}

function Sample_6_GenerateSelfSignedCertificate {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $CertReqFilePath = "req.req",
        [parameter(Mandatory=$false)] [System.String] $CertFilePath = "SelfSignedCert.crt"
    )
    openssl x509 -req -days 365 -in $CertReqFilePath -signkey $PrKFilePath -out $CertFilePath
}

function Sample_7_ExportPfx {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $CertFilePath = "SelfSignedCert.crt",
        [parameter(Mandatory=$false)] [System.String] $PassPhrase = "12345qwerty",
        [parameter(Mandatory=$false)] [System.String] $PFXFilePath = "pfx.pfx"
    )
    openssl pkcs12 -inkey $PrKFilePath -in $CertFilePath -export -out $PFXFilePath -password ('pass:' + $PassPhrase)
}

function Sample_8_ImportPfx {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "outprk.pem",
        [parameter(Mandatory=$false)] [System.String] $CertFilePath = "outCert.crt",
        [parameter(Mandatory=$false)] [System.String] $PassPhrase = "12345qwerty",
        [parameter(Mandatory=$false)] [System.String] $PFXFilePath = "pfx.pfx"
        
    )
    openssl pkcs12 -in $PFXFilePath -nokeys -nodes -password ('pass:' + $PassPhrase) | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | Set-Content $CertFilePath 
    openssl pkcs12 -in $PFXFilePath -nocerts -password ('pass:' + $PassPhrase) -nodes | sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' | Set-Content $PrKFilePath 
    openssl x509 -pubkey -noout -in ./outCert.crt | Set-Content "temppbk.pem" #export public key from cert
    Set-Content -Value "Test string" -Path temp;
    openssl dgst -sign $PrKFilePath -md_gost12_256 -binary -out temp.sig temp; #test pub key | priv key
    $ans = openssl dgst -verify "temppbk.pem" -md_gost12_256 -signature temp.sig temp #test pub key | priv key
    switch ($ans) {
        "Verified OK" {
            Write-Host -ForegroundColor Green -Object "Signature Verified"
        }
        default {
            Write-Host -ForegroundColor Red -Object "Signature NOT Verified"
        }
    }
    rm temp;
    rm temp.sig
    rm temppbk.pem
}

function Sample_9_SignCertRequest {
    #Just the same as Sample_6_GenerateSelfSignedCertificate
}

function Sample_10_Create_Attached_CAdES_BES {
    #TODO
}

function Sample_11_Verify_Attached_CAdES_BES {
    #TODO
}

function Sample_12_BuildCertChain {
    #TODO
}

function Sample_13_SignCRL {
    #TODO
}

function Sample_14_CreateOCSPResponse {
    #TODO
}

Sample_1_Generate_Gost3410_2012_KeyPair
#Sample_2_Read_Gost3410_2012_KeyPair_FromFile is not necessary / второй пример с чтением открытого/закрытого ключа, на мой взгляд, не нужен. Если очень нужно, можно воспользоваться cat prk.pem
Sample_3_Sign_And_Export_RawSignature_ToFile
Sample_4_Verify_RawSignature_ToFile
Sample_5_GenerateCertRequest
Sample_6_GenerateSelfSignedCertificate
Sample_7_ExportPfx
Sample_8_ImportPfx
#Sample_9_SignCertRequest: Just the same as Sample_6_GenerateSelfSignedCertificate
