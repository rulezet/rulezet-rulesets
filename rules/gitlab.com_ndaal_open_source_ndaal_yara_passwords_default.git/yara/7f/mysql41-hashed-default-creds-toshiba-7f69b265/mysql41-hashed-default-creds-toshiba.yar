rule mysql41_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
    $a2="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*ADE95979E72432A5AE627E51655F153B2F182A04"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*72EA7A3B37C7CF2067FD7ACD7FF596E05B9A9242"
    $a7="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}