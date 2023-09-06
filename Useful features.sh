#extract certs from sig
openssl pkcs7 -engine gost -inform PEM -in cms.sig -print_certs | awk '
BEGIN {
    flag_begin=0; flag_proceed=0; flag_end=0; n=0; filename="";
} 
{
    if ((match ($0, "subject")) != 0) {
        split($0, temp, ","); 
        for (a in temp) {
            if ((match (temp[a], "CN")) != 0) {
                split(temp[a], tmp, "=");  
                filename=(tmp[(length(tmp))]);
                filename=substr(filename,2);
                gsub(" ", "_", filename);
            };
        }
    };
    if ($0 == "-----BEGIN CERTIFICATE-----") {flag_begin=1; flag_end=0;};
    if ($0 == "-----END CERTIFICATE-----") {flag_begin=0; flag_end=1;};
    if (($0 != "-----BEGIN CERTIFICATE-----") && ($0 != "-----END CERTIFICATE-----") && (flag_end==1)) {flag_begin=0; flag_end=0;};
    if ((flag_begin==1) && (flag_proceed==0) && (flag_end==0)) {n++;};
    if (flag_begin==1) {flag_proceed=1;};
    if (flag_end==1) {flag_proceed=0;};
    if ((flag_proceed==1) || (flag_end==1)) {print ($0)> "cert_" n "_CN_" filename ".pem";};
}'
#----------------------------------------------------------------------------------------------------------------------------------


#extract signed content from base64 encoded sig
cat sig.sig | base64 --decode --ignore-garbage | openssl cms -cmsout -inform DER -print -nameopt utf8 -print | awk '
BEGIN {
    flag_start=0; flag_proceed=0;
}
{
    if (match($0, "eContent:")!=0) {flag_start=1}
    if ((flag_start==1) && (match($0, "        ")!=0)) {flag_proceed=1}
    if ((flag_proceed==1) && (match($0, "        ")==0)) {flag_start=0; flag_proceed=0}
    if (flag_proceed) {for (i=3; i<=16; i++) {printf ($i)};}
}' | sed "s|[-.]||g" | xxd -r -p | sed 's/$/ \n/' > test.txt
#----------------------------------------------------------------------------------------------------------------------------------


#convert x509 serial to bigint using bash
echo $(echo 'ibase=16;' $(openssl x509 -in user.crt -serial -noout | tr "=", "\n" | sed -n 'n;p')| bc)
#it is useful when you need to create another x509 cert with the same serial (or add 1 or 2, idk)
openssl x509 -engine gost -req -in req.req -days 365 -CA caCert.crt -CAkey caprk.pem -outform PEM -out eeCert.crt -set_serial $(echo 'ibase=16;' $(openssl x509 -in user.crt -serial -noout | tr '=', '\n' | sed -n 'n;p')| bc)
#----------------------------------------------------------------------------------------------------------------------------------
