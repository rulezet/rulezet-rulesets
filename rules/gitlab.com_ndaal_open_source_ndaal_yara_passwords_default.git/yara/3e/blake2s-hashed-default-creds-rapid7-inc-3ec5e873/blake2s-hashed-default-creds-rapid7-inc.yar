rule blake2s_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="70c9e882725bd7d8335bbe8c686b3bb03e2c656aa548f93e63d6ff34906da03c"
    $a1="70c9e882725bd7d8335bbe8c686b3bb03e2c656aa548f93e63d6ff34906da03c"
condition:
    ($a0 and $a1)
}