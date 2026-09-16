rule md5_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63d02c36e983c2f5365c74b3b5a6fb29"
    $a1="63d02c36e983c2f5365c74b3b5a6fb29"
    $a2="351325a660b25474456af5c9a5606c4e"
    $a3="351325a660b25474456af5c9a5606c4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}