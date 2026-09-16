rule sha1_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f3a7c01ee6d08a8d2d2df5acfbfae4ac891d2fc"
    $a1="4f3a7c01ee6d08a8d2d2df5acfbfae4ac891d2fc"
condition:
    ($a0 and $a1)
}