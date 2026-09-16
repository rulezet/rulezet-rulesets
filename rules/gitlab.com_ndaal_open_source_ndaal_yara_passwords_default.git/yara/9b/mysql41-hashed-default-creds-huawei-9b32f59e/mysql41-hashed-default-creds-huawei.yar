rule mysql41_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*EA487CFEF2588AF7F128B663FC8ED55BB0843949"
    $a2="*1BECA913B056B4E447CBE80FB2865A528AC0D08B"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*842A5FFFFC99A29068344CA80E52DA3B96DC2191"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*A77C2051D40C29B6480019478BB218E8E2FCB67B"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*A7DC6E2DF3C1866E2DF6AB7392537CDC7086A1A5"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}