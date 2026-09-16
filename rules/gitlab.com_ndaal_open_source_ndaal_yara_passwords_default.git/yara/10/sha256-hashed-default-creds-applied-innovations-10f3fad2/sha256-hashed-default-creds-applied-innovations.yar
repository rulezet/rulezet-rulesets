rule sha256_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3608e4bd0e693177369e17f48cdf750eb962b86aaac1bf6b50c7a46d52f7d94b"
    $a1="3608e4bd0e693177369e17f48cdf750eb962b86aaac1bf6b50c7a46d52f7d94b"
condition:
    ($a0 and $a1)
}