rule sha3_256_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a1="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
condition:
    ($a0 and $a1)
}