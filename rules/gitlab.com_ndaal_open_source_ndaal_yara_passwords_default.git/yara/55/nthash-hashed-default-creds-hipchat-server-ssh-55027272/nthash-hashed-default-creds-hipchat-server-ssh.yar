rule nthash_hashed_default_creds_hipchat_server_ssh
{
    meta:
        id = "5PVrsgc55HHghPmsm1kLWV"
        fingerprint = "ecb1137c79db5c7f34be9ac01ef70ec54b93c6a986b790b1d7e8bc4358ecc784"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hipchat_server_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45eea2f985d4befadd8051e0c1129d6a"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}