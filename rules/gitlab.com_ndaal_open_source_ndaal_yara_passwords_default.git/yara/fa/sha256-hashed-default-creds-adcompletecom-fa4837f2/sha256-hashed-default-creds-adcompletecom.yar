rule sha256_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0afb00138d8e73348ec1fe41fd3d3a8fcbd90156b263bfa5791ba0e095f42cfc"
    $a1="0afb00138d8e73348ec1fe41fd3d3a8fcbd90156b263bfa5791ba0e095f42cfc"
condition:
    ($a0 and $a1)
}