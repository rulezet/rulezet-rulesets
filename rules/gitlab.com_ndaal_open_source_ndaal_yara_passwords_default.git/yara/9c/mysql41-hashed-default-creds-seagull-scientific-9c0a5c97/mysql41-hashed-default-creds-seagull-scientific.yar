rule mysql41_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*0B0A27832C339662F96E0238AD92FCBCB992A7EA"
    $a2="*197A0CC528020173082687322D7D75EB62270AF7"
    $a3="*197A0CC528020173082687322D7D75EB62270AF7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}