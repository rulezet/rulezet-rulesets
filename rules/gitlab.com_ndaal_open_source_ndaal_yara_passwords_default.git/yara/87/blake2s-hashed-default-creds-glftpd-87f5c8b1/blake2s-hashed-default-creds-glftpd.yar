rule blake2s_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a386507813b3bb08ebf46196eebd9562867ce7580027661e67438832819b0326"
    $a1="a386507813b3bb08ebf46196eebd9562867ce7580027661e67438832819b0326"
condition:
    ($a0 and $a1)
}