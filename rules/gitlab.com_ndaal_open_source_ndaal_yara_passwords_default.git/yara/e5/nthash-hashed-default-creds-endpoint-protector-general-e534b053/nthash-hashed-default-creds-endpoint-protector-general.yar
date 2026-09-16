rule nthash_hashed_default_creds_endpoint_protector_general
{
    meta:
        id = "37QjG2GFtR6XquqltaY7vA"
        fingerprint = "ff60338ecef6891347e55a401247f3365d02ee3a00ca12e80b89becb04d7b0bf"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for endpoint_protector_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1d7a74e0d15c5f3ec35f50dad2480a3"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}