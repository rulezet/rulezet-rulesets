rule nthash_hashed_default_creds_canonical_ltd
{
    meta:
        id = "4UMkRpZKgrlphRxpNXPYEx"
        fingerprint = "6aa253962b753932cb6dd22ab29827bbca807697f1ca54167cef8d2d10c659ca"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="633bb974e1420a373991e6ae5866752b"
    $a1="633bb974e1420a373991e6ae5866752b"
condition:
    ($a0 and $a1)
}