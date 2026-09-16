rule mysql41_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8C8B90B3FAF8616F013D5183C6D45DCD88B3ADFF"
    $a1="*981C7BEB4EBCC86173BA6FF1886A9C6498CE74AC"
    $a2="*03656DDD27D1A9D3704AC3792726C616520EAEBE"
    $a3="*9BAF61170E3C7DF3B91B85A69728CF8C73B2F147"
    $a4="*4425DC70CB7653062DFAE5F805ED8DC39DCBABCC"
    $a5="*690BD7344CBD6E99C27768F246FE3494A000B297"
    $a6="*B3AEB1372CD2B5FFCDD1DCAEBB02B2DAE75FF9D8"
    $a7="*4607564515FAE6C86FC3C7AC11FB307D4C819FDA"
    $a8="*687C1D14246A0D8AB886E9B96B7DF85A9AED0D00"
    $a9="*343F1F0C5D3E962080AFF84222CA9805682ED682"
    $a10="*1958ABD79762B1A195C5D68E0A7FB53B1C5C8324"
    $a11="*5CC7B3B12136E358CEF22C6E8E5A83BB0610A616"
    $a12="*F369C17720505746FAC50A22653B95F2E59E7464"
    $a13="*0CC3FD408838BFE3282D7C0623DB31A6EBFF44FD"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}