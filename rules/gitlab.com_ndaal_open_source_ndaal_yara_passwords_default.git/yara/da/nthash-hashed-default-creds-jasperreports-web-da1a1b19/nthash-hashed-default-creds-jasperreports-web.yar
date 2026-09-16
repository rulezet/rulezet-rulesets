rule nthash_hashed_default_creds_jasperreports_web
{
    meta:
        id = "412nKdLIbATcTXzioBTtrb"
        fingerprint = "338c11970ddd521b9ac799e4b383c326dc6fe5ff131720bfea7593de7fe7f530"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d0adccbef1bff9e91b3bf97d5227655"
    $a1="7d12dddeaff695c2c74dc78043a7faa4"
    $a2="7d12dddeaff695c2c74dc78043a7faa4"
    $a3="7d12dddeaff695c2c74dc78043a7faa4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}