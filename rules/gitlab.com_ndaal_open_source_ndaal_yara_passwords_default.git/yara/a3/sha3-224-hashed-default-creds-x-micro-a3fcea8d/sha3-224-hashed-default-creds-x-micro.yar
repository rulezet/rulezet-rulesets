rule sha3_224_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
    $a1="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
    $a2="9a22b61af229f3c707eaeae364a60fd6c6717321c5b0d23a098b60d8"
    $a3="9a22b61af229f3c707eaeae364a60fd6c6717321c5b0d23a098b60d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}