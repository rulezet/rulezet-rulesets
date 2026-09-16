rule mysql41_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a1="*EFE1E8118720417EAC0066B7170C12A1126BB988"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a5="*42FC4AF4C51E10CCBE412837DBE3C90B7CD7ADF9"
    $a6="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a7="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a8="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a9="*B83A2F73F9E74C1EF54E25B4C8A06A68E40CEDF1"
    $a10="*B1DD8044491463D5279575D3E82237D749962EFD"
    $a11="*B1DD8044491463D5279575D3E82237D749962EFD"
    $a12="*57870FFA4ACFE2C83807484749C44309587F60E7"
    $a13="*02AB774F64B946E371A4B8B8F6098C39CC4987CF"
    $a14="*8BAF031297D0FC2BA25DEEC2062F5AAD3249E0AD"
    $a15="*8BAF031297D0FC2BA25DEEC2062F5AAD3249E0AD"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}