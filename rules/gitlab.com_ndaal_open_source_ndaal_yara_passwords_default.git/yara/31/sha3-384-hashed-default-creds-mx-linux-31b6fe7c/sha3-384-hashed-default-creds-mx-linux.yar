rule sha3_384_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a1="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="7d34b353bf14bef0cb10fa010c45c00b54f8679a491a90d2f1c060211b945d363b868c182065e020e48e8f7a385c41de"
    $a5="0371b75b7f47c0d4f5b1a536c9e9d0bd421a3bb2045fde76a3057d778ff6cc3127174762adc17c2045997a146859bfed"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}