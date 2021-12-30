function Sample_1_Generate_Gost3410_2012_KeyPair {
    param (
        [parameter(Mandatory=$false)] [System.String] $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)] [System.String] $PbKFilePath = "pbk.pem"
    )

    openssl genpkey -outform PEM -algorithm gost2012_256 -pkeyopt paramset:TCA -out $PrKFilePath
    openssl req -new -key $PrKFilePath -subj "/" -noout -pubkey -outform PEM -out $PbKFilePath #не знаю, как иначе получить открытый ключ. Используя команду "openssl genpkey" можно получить открытый ключ, но он будет представлен в виде координат / don't know how else to get the private key. you can get the public key using the command "openssl genpkey" , but it will be represented as a coordinates
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
    openssl pkcs12 -in $PFXFilePath -nocerts -password ('pass:' + $PassPhrase) -nodes -out $PrKFilePath
    openssl pkcs12 -in $PFXFilePath -nokeys -password ('pass:' + $PassPhrase) -nodes -out $CertFilePath
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
