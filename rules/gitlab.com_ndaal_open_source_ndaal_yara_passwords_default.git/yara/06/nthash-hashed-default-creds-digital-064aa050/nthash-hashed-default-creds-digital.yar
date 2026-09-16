rule nthash_hashed_default_creds_digital
{
    meta:
        id = "2UKWxS0rElJ5sYBzgKisjQ"
        fingerprint = "b423b284eea2c308aa72573a2d782bdfac93084438a16d6bd0238fa0da105716"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abf18b968ecdb7d2beb4b1fcaa9bf54c"
    $a1="8f33e2ebe5960b8738d98a80363786b0"
condition:
    ($a0 and $a1)
}