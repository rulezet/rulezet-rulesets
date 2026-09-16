rule sha1_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d92851a906582b06bef0110a9e72690dba1cc75"
    $a1="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="3d92851a906582b06bef0110a9e72690dba1cc75"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}