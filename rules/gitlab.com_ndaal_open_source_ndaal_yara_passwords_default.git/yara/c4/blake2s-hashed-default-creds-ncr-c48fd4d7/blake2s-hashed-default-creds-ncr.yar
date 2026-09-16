rule blake2s_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1858642eccc09de43b53250b27c1e7ba0e61439780dfcd1704e1ce2e6ee773c2"
    $a1="1858642eccc09de43b53250b27c1e7ba0e61439780dfcd1704e1ce2e6ee773c2"
condition:
    ($a0 and $a1)
}