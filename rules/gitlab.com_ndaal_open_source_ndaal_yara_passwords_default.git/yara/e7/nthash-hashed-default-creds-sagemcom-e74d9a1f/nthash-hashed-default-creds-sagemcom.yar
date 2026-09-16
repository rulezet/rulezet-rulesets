rule nthash_hashed_default_creds_sagemcom
{
    meta:
        id = "694ujSVazpefuzutuybdw2"
        fingerprint = "35d203ef0d5c8607b4b19f7d9db8bcbae2632419ef282edaee4f2f43093d7237"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sagemcom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="7ce21f17c0aee7fb9ceba532d0546ad6"
condition:
    ($a0 and $a1)
}