rule sha3_384_hashed_default_creds_ldap_account_managerlam
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ldap_account_managerlam."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="25fa5a9a5899389d961c6c0976641a1a48b6300fc68c63c92175afa1ffc57ac4a5d598991571ca11b183c27390640525"
    $a1="25fa5a9a5899389d961c6c0976641a1a48b6300fc68c63c92175afa1ffc57ac4a5d598991571ca11b183c27390640525"
condition:
    ($a0 and $a1)
}