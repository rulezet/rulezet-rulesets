rule mysql41_hashed_default_creds_linksys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FB0F82C5DA92F48F4A6586AD87B4F313A0311154"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a5="*D1D13DBB11064ACBE5BAA7A8516D722F27E258AF"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a8="*9C89B23995531AE07C2CDAD0F31654F11C30FA84"
    $a9="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}