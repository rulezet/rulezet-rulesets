rule nthash_hashed_default_creds_3ware
{
    meta:
        id = "12uua9STwOwMUCBxH6yyLC"
        fingerprint = "b3c6999eb5800cba6e70428c5be9881c8bcd9b8c9b681572b64e22ed1901d58f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3ware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e2cd4b123e92cba4a46dea7795ae3cf"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}