rule sha3_256_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d9ca96277faedad9f5613442151e23f7b4ec373b11351cff19cf6baba39a654"
    $a1="d56b05e25e7c833134dee3c29ee3419260f286bbe95f397ec0ca1959ca1aa11e"
condition:
    ($a0 and $a1)
}