rule mysql41_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*13F84CC62636F799FE455B4B4BD45DB6C02F599B"
    $a5="*13F84CC62636F799FE455B4B4BD45DB6C02F599B"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*00A51F3F48415C7D4E8908980D443C29C69B60C9"
    $a9="*CB483D388AA10B123D1FF3541953A02DFD627FDA"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}