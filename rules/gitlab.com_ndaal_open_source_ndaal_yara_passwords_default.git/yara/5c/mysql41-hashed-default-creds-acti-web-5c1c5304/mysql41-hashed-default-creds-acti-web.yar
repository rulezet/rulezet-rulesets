rule mysql41_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a3="*D89A99106002D77C1D327FC41E005919505638B0"
    $a4="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a7="*D89A99106002D77C1D327FC41E005919505638B0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}