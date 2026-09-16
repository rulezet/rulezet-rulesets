rule mysql41_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E6CC90B878B948C35E92B003C792C46C58C4AF40"
    $a1="*3C6C66E14286DAE6BA1B61D269D6C35DADCD413D"
    $a2="*E6CC90B878B948C35E92B003C792C46C58C4AF40"
    $a3="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}