$lib = @"
[DllImport("C:\\Program Files (x86)\\Crypto Pro\\CAdES Browser Plug-in\\cades.dll", SetLastError=true)]
public static extern bool CadesMsgIsType(
    IntPtr hCryptMsg,
    uint dwSignatureIndex,
    uint dwCadesType,
    ref bool pbResult
);

[DllImport("crypt32.dll", SetLastError=true)]
    public static extern IntPtr CryptMsgOpenToDecode(
    uint dwMsgEncodingType,
    uint dwFlags,
    uint dwMsgType,
    IntPtr hCryptProv,
    IntPtr pRecipientInfo,
    IntPtr pStreamInfo
);

[DllImport("crypt32.dll", SetLastError=true)]
public static extern bool CryptMsgUpdate(
    IntPtr hCryptMsg,
    byte[] pbData,
    int cbData,
    bool fFinal
);
"@
Add-Type -MemberDefinition $lib -Namespace PKI -Name CSP
$hMsg = [PKI.CSP]::CryptMsgOpenToDecode(
    0x10000,
    0,
    0,
    0,
    0,
    0
)
[void]([PKI.CSP]::CryptMsgUpdate(
    $hMsg,
    [System.IO.File]::ReadAllBytes((gi -Path '.\1.sig').FullName),
    [System.IO.File]::ReadAllBytes((gi -Path '.\1.sig').FullName).Length+1,
    $true
))
#1: B, 2: T,  3: PKCS7,  4: XLT1, 5: A
$i = 1;
Write-Host "--------------------------------------------------------------"
Write-Host "1: CAdES-BES | 2: CAdES-T | 3: PKCS#7 | 4: CAdES-X Logn Type 1"
Write-Host "--------------------------------------------------------------"
1, 0x5, 0xffff, 0 | % {
    $flag = $false
    [void]([PKI.CSP]::CadesMsgIsType(
        $hMsg,
        0x0,
        $_,
        [ref] $flag
    ))
    Write-Host -Object "$($i): result: $($flag)"
    $i++
}
