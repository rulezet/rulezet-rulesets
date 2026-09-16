rule sha1_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d92899c8cba68c81bf496197c4f0fdcb0dd44d26"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="541cc729cb85423eca10f5600d8d713aee08ad96"
    $a3="46e3d772a1888eadff26c7ada47fd7502d796e07"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}