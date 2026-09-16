rule sha512_hashed_default_creds_telco_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c5289262a2dd33c53c6d8905f57b5d957bd60e1f4d4cf4e5a6823cdab4b8fa4df6b7418af6be7493a14286b674bc3d12a961900835e7ba9d734f1bf0f2c7c32e"
    $a1="c5289262a2dd33c53c6d8905f57b5d957bd60e1f4d4cf4e5a6823cdab4b8fa4df6b7418af6be7493a14286b674bc3d12a961900835e7ba9d734f1bf0f2c7c32e"
condition:
    ($a0 and $a1)
}