rule sha3_384_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9075e698b7643bc46fc8113dc316c5a837fc915fd4b46b5f362701be8f7745accf1d447c548845535f1646e46eda4778"
    $a1="9075e698b7643bc46fc8113dc316c5a837fc915fd4b46b5f362701be8f7745accf1d447c548845535f1646e46eda4778"
condition:
    ($a0 and $a1)
}