rule sha224_hashed_default_creds_nexsan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nexsan."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91f0572f12a77295e530583937e9d463c37c11760562e189cbb8188c"
    $a1="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
condition:
    ($a0 and $a1)
}