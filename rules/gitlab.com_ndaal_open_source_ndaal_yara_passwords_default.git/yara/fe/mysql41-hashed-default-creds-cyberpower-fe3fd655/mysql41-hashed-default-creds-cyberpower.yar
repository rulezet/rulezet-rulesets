rule mysql41_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C466EF14D716078FCDA348CB3648F360A5E46719"
    $a1="*C466EF14D716078FCDA348CB3648F360A5E46719"
    $a2="*C466EF14D716078FCDA348CB3648F360A5E46719"
    $a3="*61342F052E319D36B0E6C984AF680C4087210453"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}