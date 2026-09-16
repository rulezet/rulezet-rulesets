rule nthash_hashed_default_creds_guardone
{
    meta:
        id = "49rQffDvf0ulFBoOxAvuHl"
        fingerprint = "a2694dd3e895c0a15c88b6f06f7c62205eb75d14da969b019c60721d17e00d12"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa40632a7b38e63c4dda8edabce89c16"
    $a1="9d95d5a7a19e3ad3223f5f9722bc3654"
condition:
    ($a0 and $a1)
}