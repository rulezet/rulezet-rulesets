rule sha1_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2abd55e001c524cb2cf6300a89ca6366848a77d5"
    $a1="329cb8b6ba8c427be7c09b298295c655415c7ac9"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="fe96dd39756ac41b74283a9292652d366d73931f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}