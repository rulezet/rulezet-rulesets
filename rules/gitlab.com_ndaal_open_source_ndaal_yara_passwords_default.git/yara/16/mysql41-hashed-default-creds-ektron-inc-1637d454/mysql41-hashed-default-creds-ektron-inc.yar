rule mysql41_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E5D6C43FDCC382680C128B8F5B072EDCEEB122D7"
    $a1="*E5D6C43FDCC382680C128B8F5B072EDCEEB122D7"
    $a2="*03E6215E708C634B1CEEEAFF0018CF07D7356A8F"
    $a3="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}