rule sha224_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e0537f07091ae104db4a8b939b3c47b1b8c2f4f38c55ee45f871b22b"
    $a1="d9013712ed33598db5fd4ce9b8ed8709bc807fa71b361e9c7e2089a6"
condition:
    ($a0 and $a1)
}