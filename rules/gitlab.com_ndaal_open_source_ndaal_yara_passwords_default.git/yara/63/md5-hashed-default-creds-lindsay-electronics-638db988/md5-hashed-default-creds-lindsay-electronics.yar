rule md5_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6e9f5d5d8fb4be11d981eba8db34c14"
    $a1="99fedb09f0f5da90e577784e5f9fdc23"
    $a2="e6e9f5d5d8fb4be11d981eba8db34c14"
    $a3="e6e9f5d5d8fb4be11d981eba8db34c14"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}