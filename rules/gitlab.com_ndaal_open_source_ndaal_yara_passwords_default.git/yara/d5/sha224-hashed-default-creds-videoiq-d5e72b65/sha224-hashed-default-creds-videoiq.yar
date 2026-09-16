rule sha224_hashed_default_creds_videoiq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
    $a1="64cd35385184bab91d1f394b3f64e935fd4bc939333c486a70d9a946"
condition:
    ($a0 and $a1)
}