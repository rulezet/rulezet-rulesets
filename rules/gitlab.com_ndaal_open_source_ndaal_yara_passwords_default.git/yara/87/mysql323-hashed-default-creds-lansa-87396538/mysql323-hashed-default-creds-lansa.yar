rule mysql323_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="7b16873b22ae4966"
    $a3="7b16873b22ae4966"
    $a4="5d2e19393cc5ef67"
    $a5="0f37bc1e4c7136c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}