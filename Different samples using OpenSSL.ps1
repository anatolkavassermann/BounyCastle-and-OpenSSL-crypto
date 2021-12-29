function Sample_1_Generate_Gost3410_2012_KeyPair {
    param (
        [parameter(Mandatory=$false)]
        [System.String]
        $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)]
        [System.String]
        $PbKFilePath = "pbk.pem"
    )

    openssl genpkey -outform PEM -algorithm gost2012_256 -pkeyopt paramset:TCA -out $PrKFilePath
    openssl req -new -key $PrKFilePath -subj "/" -noout -pubkey -outform PEM -out $PbKFilePath #не знаю, как иначе получить закрытый ключ. Используя команду "openssl genpkey" можно получить открытый ключ, но он будет представлен в виде координат
}
function Sample_3_Sign_And_Export_RawSignature_ToFile {
    param (
        [parameter(Mandatory=$false)]
        [System.String]
        $PrKFilePath = "prk.pem",
        [parameter(Mandatory=$false)]
        [System.String]
        $ToBeSignedFilePath = "to_be_signed.txt",
        [parameter(Mandatory=$false)]
        [System.String]
        $RAWSigFilePath = "to_be_signed.txt.sig"
    )

    openssl dgst -sign $PrKFilePath -md_gost12_256 -binary -out $RAWSigFilePath $ToBeSignedFilePath
}

function Sample_4_Verify_RawSignature_ToFile {
    param (
        [parameter(Mandatory=$false)]
        [System.String]
        $PbKFilePath = "pbk.pem",
        [parameter(Mandatory=$false)]
        [System.String]
        $ToBeSignedFilePath = "to_be_signed.txt",
        [parameter(Mandatory=$false)]
        [System.String]
        $RAWSigFilePath = "to_be_signed.txt.sig"
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

Sample_1_Generate_Gost3410_2012_KeyPair
#Sample_2 is not necessary / второй пример с чтением открытого/закрытого ключа, на мой взгляд, не нужен. Если очень нужно, можно воспользоваться cat prk.pem
Sample_3_Sign_And_Export_RawSignature_ToFile
Sample_4_Verify_RawSignature_ToFile
