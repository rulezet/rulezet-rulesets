rule sha224_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d4fc8435c5503ecbf47b558a3a24478da85362198e52e01c7a5fe4a"
    $a1="350ad7bd8406d1e7970ba86a036b4e531f9f4b1fcd5b7a1b19f8444e"
condition:
    ($a0 and $a1)
}