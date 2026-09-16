rule mysql323_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="7b57f28428847751"
    $a2="1bea6e365840ca17"
    $a3="6a77f1277b51f67f"
    $a4="56b6113a2cefc6ea"
    $a5="6a77f1277b51f67f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}