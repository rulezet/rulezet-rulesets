rule nthash_hashed_default_creds_regpnuacir
{
    meta:
        id = "1q8MhFZv5276foT2hh8nAX"
        fingerprint = "af3d0668d80f681704e0f5fbbb6cb1c01f31402a746cd61b766c75e82f0d1a2a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12318aa9e8464e83d0d99ef189f37ae9"
    $a1="f0470cb823905f34632d64ea9f78f662"
condition:
    ($a0 and $a1)
}