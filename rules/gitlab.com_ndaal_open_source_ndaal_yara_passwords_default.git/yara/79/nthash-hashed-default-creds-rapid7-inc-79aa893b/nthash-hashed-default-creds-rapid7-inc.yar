rule nthash_hashed_default_creds_rapid7_inc
{
    meta:
        id = "47YrCk9QwZIsUFn6P3S3WV"
        fingerprint = "cde4745c33387509c67b00b5dd36218e9194641e7a1f6560204d985a6c5a14a8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="27c433245e4763d074d30a05aae0af2c"
    $a1="27c433245e4763d074d30a05aae0af2c"
condition:
    ($a0 and $a1)
}