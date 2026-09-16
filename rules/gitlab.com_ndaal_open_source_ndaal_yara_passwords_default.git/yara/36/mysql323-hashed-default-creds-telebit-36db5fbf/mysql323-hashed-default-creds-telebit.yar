rule mysql323_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d89770b0d299d60"
    $a1="3d89770b0d299d60"
    $a2="4e3261527dec15ee"
    $a3="6af6992c7e70f8d5"
    $a4="7e888a35354f24ff"
    $a5="6af6992c7e70f8d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}