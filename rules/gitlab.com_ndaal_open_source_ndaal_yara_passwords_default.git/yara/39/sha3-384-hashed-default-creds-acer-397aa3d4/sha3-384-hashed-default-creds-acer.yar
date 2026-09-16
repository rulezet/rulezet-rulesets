rule sha3_384_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04c7448cbbe633402510adaed5f9ece5d9016c048b4fb07c6d9c6e7b4ca8662582b76e7b2bc0fe5fa56dd75893c74c5a"
    $a1="04c7448cbbe633402510adaed5f9ece5d9016c048b4fb07c6d9c6e7b4ca8662582b76e7b2bc0fe5fa56dd75893c74c5a"
condition:
    ($a0 and $a1)
}