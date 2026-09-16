rule mysql323_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b5a31ea36bebc2b"
    $a1="43e9a4ab75570f5b"
    $a2="3b5a31ea36bebc2b"
    $a3="1e0c530062ec7e17"
    $a4="7de2fe8a3d64624b"
    $a5="1731959a18d86d30"
    $a6="7de2fe8a3d64624b"
    $a7="115d27f60f8521e4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}