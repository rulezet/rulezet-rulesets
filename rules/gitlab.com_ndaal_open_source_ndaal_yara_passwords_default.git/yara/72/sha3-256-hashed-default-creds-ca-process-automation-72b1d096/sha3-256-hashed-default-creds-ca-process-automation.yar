rule sha3_256_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ca72859d6fea775126c5b8581ffabfbfb8e8ca0da26bd8da9650ffde5d01d64"
    $a1="7ca72859d6fea775126c5b8581ffabfbfb8e8ca0da26bd8da9650ffde5d01d64"
condition:
    ($a0 and $a1)
}