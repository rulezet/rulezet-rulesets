rule sha1_hashed_default_creds_draytek
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for draytek."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="59616018b31b7965576f5d03340f97b0106e87a1"
    $a4="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a5="e00ef351a5452f633e5071782cd550bc0afb44db"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}