rule md5_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="388d33adeb7f579156ee4a0c86777760"
    $a1="388d33adeb7f579156ee4a0c86777760"
    $a2="1ba1910b5b36c57ca5a6bf1134186f00"
    $a3="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}