rule sha3_224_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="5f5c82ceba48805254828ca4c8e61e236fd9d04d948e5f05169d35a4"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="cace7202470e352a284a14980c3cb8f5f4056a9b687b3688a37449ce"
    $a5="53091ca7ecf9db4678e492b0b09a6c1c8879ded80549295c7231c92e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}