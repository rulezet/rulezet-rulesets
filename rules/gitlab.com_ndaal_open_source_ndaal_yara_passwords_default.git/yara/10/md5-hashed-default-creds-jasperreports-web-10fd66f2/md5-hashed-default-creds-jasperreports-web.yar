rule md5_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a4dc9133d5f3b6d9fff778aff361961"
    $a1="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a2="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a3="0d7cc6fdf3d432b7f0855713c50a1dbe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}