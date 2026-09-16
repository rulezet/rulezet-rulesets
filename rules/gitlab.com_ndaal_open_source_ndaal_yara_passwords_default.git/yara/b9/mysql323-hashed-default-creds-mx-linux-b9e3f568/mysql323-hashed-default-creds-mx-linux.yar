rule mysql323_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d98684b668859ca"
    $a1="6d98684b668859ca"
    $a2="67457e226a1a15bd"
    $a3="67457e226a1a15bd"
    $a4="65a7e2964d411a0b"
    $a5="3e72b5160f5197eb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}