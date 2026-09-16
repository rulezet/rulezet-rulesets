rule sha256_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90a2b51b1e75d226f56e57edf479e5ccb8b4d70ebb134ad2be772badfb9ea67c"
    $a1="6220b3e1f255f8e29b87488abab1bde126a6bbb44c62bf9b297b3d20347f8b4e"
condition:
    ($a0 and $a1)
}