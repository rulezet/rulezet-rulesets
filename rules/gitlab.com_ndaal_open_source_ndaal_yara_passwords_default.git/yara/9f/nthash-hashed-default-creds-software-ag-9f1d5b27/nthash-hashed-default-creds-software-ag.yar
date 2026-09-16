rule nthash_hashed_default_creds_software_ag
{
    meta:
        id = "15a6DMVJGLwdNe1kY5PJKv"
        fingerprint = "98b94e9d433a95462adc6e6a8ed81beff8889d6271fbf22f7bd1387ca8c05e4a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for software_ag."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be85ca9e6c44e05c9b2b50d681186a35"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}