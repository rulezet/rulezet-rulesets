rule sha3_256_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5a5207a8729b1f709cb710311751eb2fc8acad5a1fb8ac991b736e69b6529a3"
    $a1="865800f9b7760c25f543722e0f21ecf224da3567f0ab921f04449135f30e5375"
condition:
    ($a0 and $a1)
}