rule sha224_hashed_default_creds_us_robotic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotic."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b09ae657f9bb26f9e761879efebdb8dd5b3e72f8061271219b52cf72"
    $a1="b09ae657f9bb26f9e761879efebdb8dd5b3e72f8061271219b52cf72"
condition:
    ($a0 and $a1)
}