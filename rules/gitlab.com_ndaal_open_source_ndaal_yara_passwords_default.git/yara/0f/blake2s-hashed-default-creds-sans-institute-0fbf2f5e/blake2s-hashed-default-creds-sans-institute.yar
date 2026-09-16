rule blake2s_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0863006984ebeb7bbbe932b2f0f7bd4e8d9fa28be7bb9574dc1503652f06232a"
    $a1="1de5b883995c7a5c6d50dca26924db50712eec67303f6fc4ef163b8724ff3784"
condition:
    ($a0 and $a1)
}