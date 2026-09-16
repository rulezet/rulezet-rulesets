rule nthash_hashed_default_creds_comodo_group_inc
{
    meta:
        id = "7EGZbXtYPU9zIrEZce70sj"
        fingerprint = "3ea4069a6b232d6bc456dbb9776ad7eec47be19a6258a0ed7ce733ec17d7f076"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="338349e7a06a8be50173e92043eac1f1"
    $a1="338349e7a06a8be50173e92043eac1f1"
condition:
    ($a0 and $a1)
}