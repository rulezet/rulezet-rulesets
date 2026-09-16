rule sha3_256_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5985b182b2b67a822ecaad7ee44636333e2310b57533e7b9c95e6c08a7c7932"
    $a1="e5985b182b2b67a822ecaad7ee44636333e2310b57533e7b9c95e6c08a7c7932"
condition:
    ($a0 and $a1)
}