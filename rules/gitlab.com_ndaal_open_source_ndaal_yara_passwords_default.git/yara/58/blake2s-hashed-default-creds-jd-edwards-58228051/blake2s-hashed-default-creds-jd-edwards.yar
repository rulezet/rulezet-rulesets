rule blake2s_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe53f356ecaa92ac93d5c5a615a3e47e5dc8f783e6a4f72b261a0f261003e90d"
    $a1="fe53f356ecaa92ac93d5c5a615a3e47e5dc8f783e6a4f72b261a0f261003e90d"
condition:
    ($a0 and $a1)
}