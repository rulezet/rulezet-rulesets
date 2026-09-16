rule nthash_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        id = "2FMGUh0mWSK0RF3RCYhnyv"
        fingerprint = "aac31666534432567cfa2e0e0a5f3224310efff2312e69eb5907231a83bc7b9c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69943c5e63b4d2c104dbbcc15138b72b"
    $a1="e271270abe57c0ff0d2b1d43dd5ced93"
    $a2="69943c5e63b4d2c104dbbcc15138b72b"
    $a3="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}