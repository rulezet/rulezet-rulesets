rule sha1_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
    $a1="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
    $a2="1044690fb7396009f731d125bd18e634fd77ad28"
    $a3="1044690fb7396009f731d125bd18e634fd77ad28"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}