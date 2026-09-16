rule mysql41_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8562186C9D7B7F0E7FF8E38962CAA1AE9B73C1EF"
    $a1="*8562186C9D7B7F0E7FF8E38962CAA1AE9B73C1EF"
condition:
    ($a0 and $a1)
}