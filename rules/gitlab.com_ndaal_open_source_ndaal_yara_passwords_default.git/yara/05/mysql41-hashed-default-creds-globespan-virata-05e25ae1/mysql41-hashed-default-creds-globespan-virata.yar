rule mysql41_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2227A3826361E66ACFA874DD19F8C83B3C27AE9D"
    $a1="*2227A3826361E66ACFA874DD19F8C83B3C27AE9D"
condition:
    ($a0 and $a1)
}