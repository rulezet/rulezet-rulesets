rule mysql323_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62baeaa14e175d75"
    $a1="43e9a4ab75570f5b"
    $a2="04f2bda715b7a001"
    $a3="45b07dcb6b0e20fb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}