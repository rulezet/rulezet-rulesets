rule sha256_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50f08e64c5a6192c58961a72ca0b5fcb06f1a09d49e3d012619c2050b84c9b00"
    $a1="50f08e64c5a6192c58961a72ca0b5fcb06f1a09d49e3d012619c2050b84c9b00"
condition:
    ($a0 and $a1)
}