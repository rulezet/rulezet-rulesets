rule mysql323_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="016537a06c496eaa"
    $a1="43e9a4ab75570f5b"
    $a2="43e9a4ab75570f5b"
    $a3="43e9a4ab75570f5b"
    $a4="22e3be3e311d37ea"
    $a5="43e9a4ab75570f5b"
    $a6="65df5fc82365a505"
    $a7="674257506a0ff8e8"
    $a8="2515f02914fd1111"
    $a9="2515f02914fd1111"
    $a10="65df5fc82365a505"
    $a11="67457e226a1a15bd"
    $a12="67457e226a1a15bd"
    $a13="67457e226a1a15bd"
    $a14="65df5fc82365a505"
    $a15="22e3be3e311d37ea"
    $a16="22e3be3e311d37ea"
    $a17="22e3be3e311d37ea"
    $a18="22e3be3e311d37ea"
    $a19="1a204533660f1fc3"
    $a20="22e3be3e311d37ea"
    $a21="2515f02914fd1111"
    $a22="10804243026ede9e"
    $a23="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}