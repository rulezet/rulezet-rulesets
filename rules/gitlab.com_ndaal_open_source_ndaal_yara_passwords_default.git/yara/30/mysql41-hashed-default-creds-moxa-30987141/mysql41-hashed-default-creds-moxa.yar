rule mysql41_hashed_default_creds_moxa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for moxa."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}