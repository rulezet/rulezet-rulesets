rule nthash_hashed_default_creds_super_micro_computer_inc
{
    meta:
        id = "2hnQ5gaWD4HJIz4daaLJik"
        fingerprint = "c5fc244e31673ec2dd9faa5d8cfbbdf3aad577040bd34af9839313449c186bf8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for super_micro_computer_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="11a01c4a0f2f228796c93fa0ca1a634d"
    $a1="11a01c4a0f2f228796c93fa0ca1a634d"
condition:
    ($a0 and $a1)
}