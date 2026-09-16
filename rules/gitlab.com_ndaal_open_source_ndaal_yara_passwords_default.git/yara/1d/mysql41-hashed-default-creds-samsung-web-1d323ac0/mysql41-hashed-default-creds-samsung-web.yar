rule mysql41_hashed_default_creds_samsung_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E6EDEDB136E4E42A35025BE0FD932729AD3941BD"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*C05C68552A6E2FC59ECC2FF0C50D51BB930F47FC"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}