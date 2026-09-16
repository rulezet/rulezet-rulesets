rule sha224_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="364414f23829c16fc363869401d1f2e6dbedf732600cd5c4844fb614"
    $a1="364414f23829c16fc363869401d1f2e6dbedf732600cd5c4844fb614"
condition:
    ($a0 and $a1)
}