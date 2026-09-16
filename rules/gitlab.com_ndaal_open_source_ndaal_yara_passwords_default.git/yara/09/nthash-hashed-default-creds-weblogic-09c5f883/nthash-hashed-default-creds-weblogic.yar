rule nthash_hashed_default_creds_weblogic
{
    meta:
        id = "5OuaEZUZ0qBWYqjiXnP6rc"
        fingerprint = "3c68d9df9e3a1d00512eb58627d63c82dab819b46ef4444a2a2092f80908e26c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50838b21bdef4bbe69c770f8ee7169fb"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1)
}