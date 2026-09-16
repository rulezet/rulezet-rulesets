rule sha256_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dd40ae398e2e3f5e55467c3b0e189bea1c8b0f0bded7b08973ac3779c40a30f"
    $a1="704c886409ad26cb37f4df84782494a070b60c4789a6146c2a899577236d37d4"
condition:
    ($a0 and $a1)
}