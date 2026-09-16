rule sha1_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="745d0b2380e21353d526db47a87158f2065563ee"
    $a1="afc848c316af1a89d49826c5ae9d00ed769415f3"
    $a2="f76c18918cc75fb69ce299338a13f24278ddbef1"
    $a3="afc848c316af1a89d49826c5ae9d00ed769415f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}