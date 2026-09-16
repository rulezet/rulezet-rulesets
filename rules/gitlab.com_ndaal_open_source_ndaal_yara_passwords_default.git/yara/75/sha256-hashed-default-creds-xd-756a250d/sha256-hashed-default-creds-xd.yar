rule sha256_hashed_default_creds_xd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cf2283ad6ef0a3266059b418a73f8479338233ea2c4bcd3c1f51c39f13ae7dc"
    $a1="8cf2283ad6ef0a3266059b418a73f8479338233ea2c4bcd3c1f51c39f13ae7dc"
condition:
    ($a0 and $a1)
}