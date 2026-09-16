rule nthash_hashed_default_creds_arun
{
    meta:
        id = "3cvyUp739O70bcNJCrRfOP"
        fingerprint = "242feb0cd11d421409388838df56c603cea303094c50efb93676c6647fa7ef42"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for arun."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="193a5267f55d05d54503ff508c9d6566"
    $a1="3dbde697d71690a769204beb12283678"
condition:
    ($a0 and $a1)
}