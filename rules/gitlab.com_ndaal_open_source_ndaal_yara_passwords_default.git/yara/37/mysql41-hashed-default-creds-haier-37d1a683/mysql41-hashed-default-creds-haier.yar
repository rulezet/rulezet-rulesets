rule mysql41_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7FEF17ED6266D83F24CFA0C5055DE1B9893ABB6F"
    $a1="*6BCB2C05FBBAC8F8AE7A174CFC8D2FAA87E9E3E7"
condition:
    ($a0 and $a1)
}