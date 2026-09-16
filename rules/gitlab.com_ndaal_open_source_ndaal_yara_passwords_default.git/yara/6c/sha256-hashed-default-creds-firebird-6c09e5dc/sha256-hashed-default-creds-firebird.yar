rule sha256_hashed_default_creds_firebird
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48c5a1d217fe85082464d2ca1e90a16d15464fabe20f8610d79b63aa58797b9b"
    $a1="d42c104a926912d66fc148da987606648ae8e4ff88b21c810e51f8c47b3b7064"
condition:
    ($a0 and $a1)
}