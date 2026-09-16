rule mysql323_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="43e9a4ab75570f5b"
    $a2="5d2e19393cc5ef67"
    $a3="5f7bee3e78957ef2"
    $a4="4701175b460f3f84"
    $a5="4701175b460f3f84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}