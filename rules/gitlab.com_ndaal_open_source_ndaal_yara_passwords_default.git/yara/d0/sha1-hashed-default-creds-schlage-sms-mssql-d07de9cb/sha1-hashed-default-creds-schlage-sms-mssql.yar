rule sha1_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1133215157ff92cc61a17c4a6385e7e9c18e890f"
    $a1="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a2="1133215157ff92cc61a17c4a6385e7e9c18e890f"
    $a3="4b6b362343a742ad40743f3e18e9770236076746"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}