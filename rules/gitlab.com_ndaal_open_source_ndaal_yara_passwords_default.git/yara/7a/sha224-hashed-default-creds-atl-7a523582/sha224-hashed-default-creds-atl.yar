rule sha224_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb14c2341d28bb03b0fd355ff026936625ef586c5d5dc20ac370b12"
    $a1="7a1aa63dd4f07ef81ed2dc00fd3660a61d353e937ad9261f18e86667"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}