rule mysql41_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*D89A99106002D77C1D327FC41E005919505638B0"
    $a4="*063A1C905459DC7F4EBF365C92140F617757D62B"
    $a5="*063A1C905459DC7F4EBF365C92140F617757D62B"
    $a6="*8B4403525C71802B094EDD5A3E9304C7094A13CB"
    $a7="*18B79090A9D7BBD4985A1CDB980345A55AD5796E"
    $a8="*71D5B079EE7ED147D46628AB448EE77BDF6989D8"
    $a9="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a10="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a11="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a12="*F1548D3C7B8B91CEA08E350B1CE88698613530C9"
    $a13="*F1548D3C7B8B91CEA08E350B1CE88698613530C9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}