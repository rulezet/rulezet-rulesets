rule nthash_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        id = "2FgMmtgUkNvb9GYCYDzZEL"
        fingerprint = "4c740e9fb97c29c66628f38a3a83a4aa2f21acb7d0479e4ca652baf6dd3e9c8e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="689e456db2d241c0ccd5c9abf86ff491"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="656dd714d7e4e8a16380d92ef4aac194"
    $a3="655c0f51daeea46804a09e7ec4d2ad4c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}