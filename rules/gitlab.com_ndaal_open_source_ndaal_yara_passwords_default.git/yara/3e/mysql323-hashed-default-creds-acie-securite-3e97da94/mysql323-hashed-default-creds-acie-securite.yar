rule mysql323_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="2d6aa2fc7543c72f"
    $a2="3aaa068a3b9e17f1"
    $a3="2d6aa2fc7543c72f"
    $a4="0f37f2bd198f9f92"
    $a5="2d6aa2fc7543c72f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}