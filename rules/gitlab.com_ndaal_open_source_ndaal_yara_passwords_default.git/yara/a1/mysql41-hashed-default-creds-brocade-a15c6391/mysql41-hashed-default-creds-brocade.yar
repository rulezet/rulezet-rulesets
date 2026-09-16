rule mysql41_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B20120C7AFFAC54E03C5FF00F91AA4715E9F0903"
    $a1="*3D68B1902EC87DAF014FB0DB2405B3682C6E43C9"
    $a2="*8800A1463E51A6BB283B6073B5C5E1AAE7CE86AA"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a7="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a8="*E6EF693E2F194D0B7250F627E6DEC3D8F808AD05"
    $a9="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a10="*C580B972BDCA3A352CEAC69369B47D3672122DFC"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*74E352D295832E0557641660482EA77BC2253E3D"
    $a13="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}