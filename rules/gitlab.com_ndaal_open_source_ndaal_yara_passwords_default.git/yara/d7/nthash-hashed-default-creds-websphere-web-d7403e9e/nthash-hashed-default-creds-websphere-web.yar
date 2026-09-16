rule nthash_hashed_default_creds_websphere_web
{
    meta:
        id = "oztT8U5DjHk9zvJkWBaGd"
        fingerprint = "66a1461601e5a62aa20b3820fd0e376b7fbb2d1adb4b51fa0259ad95ca447966"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for websphere_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1)
}