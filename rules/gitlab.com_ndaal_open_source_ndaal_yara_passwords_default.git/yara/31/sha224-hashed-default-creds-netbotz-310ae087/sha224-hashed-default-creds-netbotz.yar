rule sha224_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21616385c30d1c51a7b5ed11c042503adf2d2b374a9cad0cb8b34417"
    $a1="21616385c30d1c51a7b5ed11c042503adf2d2b374a9cad0cb8b34417"
condition:
    ($a0 and $a1)
}