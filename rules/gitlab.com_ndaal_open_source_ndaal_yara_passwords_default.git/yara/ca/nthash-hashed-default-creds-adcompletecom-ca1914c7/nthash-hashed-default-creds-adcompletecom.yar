rule nthash_hashed_default_creds_adcompletecom
{
    meta:
        id = "7DYCvc529x47u14BkExrJD"
        fingerprint = "1353ff18f6746f4f091aab3264aa520869a6ecd5bfd0c03a0082d1b6502b4947"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="580b16d486d8d2cafa00b314d41fa396"
    $a1="580b16d486d8d2cafa00b314d41fa396"
condition:
    ($a0 and $a1)
}