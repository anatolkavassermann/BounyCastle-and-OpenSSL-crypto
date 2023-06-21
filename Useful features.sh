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


#Сконвертировать контейнер КриптоПро в pfx, который съест Vipnet csp
#важно. тестировалось на wsl 2.0, ubuntu 20.04.06, openssl 1.1.1f
sudo apt update;
sudo apt install git perl cmake make gcc libssl-dev python3-pip zstd;
cd ~/;
git clone --branch=openssl_1_1_1 https://github.com/gost-engine/engine.git ./gost-engine/engine;
cd gost-engine/engine/;
cmake . -DOPENSSL_ENGINES_DIR=/usr/lib/x86_64-linux-gnu/engines-1.1/;
make;
sudo cp ./bin/gost.so /usr/lib/x86_64-linux-gnu/engines-1.1/;
#Далее надо отредачить конфиг /etc/ssl/openssl.conf согласно инструкции тут: https://gist.github.com/shadz3rg/7badec13e154751116a6446fe9f61906
openssl engine; #нужно проверить, что появился gost

cd ~/;
git clone https://github.com/li0ard/cpfx.git ./cpfx;
cd ./cpfx;
pip3 install asn1==2.6.0;
#возникла какая-то фигня с установкой через pip pyderasn-9.3 и pygost-5.11. Ставим это все вручную
wget http://www.pyderasn.cypherpunks.ru/download/pyderasn-9.3.tar.zst;
zstd -d < pyderasn-9.3.tar.zst | tar xf -;
cd pyderasn-9.3/;
sudo python3 setup.py install;
cd ~/cpfx;
wget http://www.pygost.cypherpunks.ru/pygost-5.11.tar.zst;
zstd -d < pygost-5.11.tar.zst | tar xf -;
cd pygost-5.11;
sudo python3 setup.py install;

cd ~/cpfx;
python3 cpfx.py <путь до pfx> #там будет предложено ввести пароль от pfx, лучше скопировать pfx в cpfx
openssl pkcs12 -in <путь до pfx> -password pass:<парль от pfx> -nokeys | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform PEM -out cert.pem
openssl pkcs12 -engine gost -export -inkey <путь до файла, который создал cpfx> -in cert.pem -out pfx.pfx -password pass:1 -keypbe gost89 -certpbe gost89 -macalg md_gost12_256
#файл pfx.pfx нужно скорпить vipnet
#----------------------------------------------------------------------------------------------------------------------------------
