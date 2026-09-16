rule nthash_hashed_default_creds_schneider_m340ftp
{
    meta:
        id = "67nG4foCvf8FxXjeD4ZVIp"
        fingerprint = "bcd88ce5c8736136b97ef783e538088ef19d1cdd7110627dc10b6fed64352af5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340ftp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e768fd2ff41b87534f7aef3e4516adf3"
    $a1="9fc6f8f7b33dab7f3cba2fac269cc3a6"
condition:
    ($a0 and $a1)
}