rule nthash_hashed_default_creds_apple_jailbroken_device_ssh
{
    meta:
        id = "4s81hxTEOLbu1ZuX1OPMGX"
        fingerprint = "e863b81b2eb5915694acc6b1aec93dfd91604d9f9eba5dbc87c4735a5a003005"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apple_jailbroken_device_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a06f7868e4f85e60a204c14be4be3e7"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="2a4fe9fc69b28fcf4e0461cf6694c46c"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}