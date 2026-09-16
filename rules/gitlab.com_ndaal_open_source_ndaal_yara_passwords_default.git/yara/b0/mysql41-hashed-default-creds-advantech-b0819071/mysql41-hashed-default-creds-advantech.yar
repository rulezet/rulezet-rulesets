rule mysql41_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4B561E28424F31FCD13DD9D1DE3B988583620C87"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a7="*5A5DF4CECE1D2AFA40F5B70DF940300F8E64E77B"
    $a8="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a9="*D89A99106002D77C1D327FC41E005919505638B0"
    $a10="*2DF3063C523DF16DEFB8A454F9DA045D92D509BA"
    $a11="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}