rule mysql41_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*531E182E2F72080AB0740FE2F2D689DBE0146E04"
    $a1="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a2="*4CA5EE9EC5AECDC8F8A158FB36427D5D8AD7F6F4"
    $a3="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a4="*C4A4F6754CCF00807FD77192DB87EDBDD55F9C73"
    $a5="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a6="*5F794C1DDCBE3964E79E87A283AC76BDB72D307F"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*1ACC14962BDBE92DEA39DC99EAF51B8312B1D425"
    $a9="*DBF1E5C3BB3C57AD4966C29169B186DD27E8D211"
    $a10="*531E182E2F72080AB0740FE2F2D689DBE0146E04"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}