rule sha512_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a1="10f296fd46a886571820201a5ec6790b7ea0eb72d518ee4a3bea0256be1ac5023a5baf2ae990dc948b8de2dab1fe92f1b63cd4d2256e4fcdfc85c01c68ade427"
    $a2="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a3="99d45477c102b8c50db133f2bc2397e01e3e769eb58bacb3fe219c4b73390bde6843807217124f5a2bee6e05504daf859f5bc060bf71576506f23392aab44b6e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}