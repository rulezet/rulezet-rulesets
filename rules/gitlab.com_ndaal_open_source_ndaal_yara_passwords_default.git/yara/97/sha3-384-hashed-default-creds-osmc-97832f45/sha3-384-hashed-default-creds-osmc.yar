rule sha3_384_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da18d049be7c22110363e1c90a68f6daef0eeaa11266ee3d134e599f979b19fef65b4f36a3381bd350b4fdf7bcd92d88"
    $a1="da18d049be7c22110363e1c90a68f6daef0eeaa11266ee3d134e599f979b19fef65b4f36a3381bd350b4fdf7bcd92d88"
condition:
    ($a0 and $a1)
}