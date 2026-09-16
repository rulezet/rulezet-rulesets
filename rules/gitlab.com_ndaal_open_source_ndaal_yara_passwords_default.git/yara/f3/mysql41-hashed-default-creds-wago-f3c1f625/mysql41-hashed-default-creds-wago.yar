rule mysql41_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5239FBCDF33B7C022281640666A7F70A86961CCD"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a3="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a4="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a6="*E5CA489DAEC42F3DEE604B064704C788070FEC79"
    $a7="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a8="*F8DD1ECF9A26FBC344692D82E4C030AEF1A178F2"
    $a9="*3FE3EA4DA8ADC44BCAD5588421C4C14C2A49760B"
    $a10="*5239FBCDF33B7C022281640666A7F70A86961CCD"
    $a11="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}