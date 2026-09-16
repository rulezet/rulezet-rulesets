rule sha256_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe68a21fc76bba7b3a3d8e454eca8cd258de68fd08dddf035f23ddbdce6fc049"
    $a1="fe68a21fc76bba7b3a3d8e454eca8cd258de68fd08dddf035f23ddbdce6fc049"
condition:
    ($a0 and $a1)
}