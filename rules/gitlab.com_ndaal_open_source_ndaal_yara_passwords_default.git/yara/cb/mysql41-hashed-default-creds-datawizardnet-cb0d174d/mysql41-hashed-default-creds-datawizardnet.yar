rule mysql41_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D722CD32A917D7AC0E9955ED484D639033A514C4"
    $a1="*4702A90989423445372DA76271286CF9621AF9D8"
    $a2="*0C1648C40981C5CA7B0410D41CB3ED8C43E05388"
    $a3="*4702A90989423445372DA76271286CF9621AF9D8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}