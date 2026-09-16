rule mysql41_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*4219D1204C5D93359DBB1E19CFE3F302A6C4A8AF"
    $a3="*4219D1204C5D93359DBB1E19CFE3F302A6C4A8AF"
    $a4="*4702A90989423445372DA76271286CF9621AF9D8"
    $a5="*4702A90989423445372DA76271286CF9621AF9D8"
    $a6="*906FE1DE9074304BFCFC319F260785D2430AE335"
    $a7="*BEB17E9980C9B26AA7FB0F3DDD2AAD2341B0F4E2"
    $a8="*1B2BC0862A474E37B90DCA121AE9D8F4736E45D1"
    $a9="*9C54F5F467D12155648B4F363D38B6B7DBC64C37"
    $a10="*F2C9D516090963EBE613ECE16924ED855487B219"
    $a11="*F2C9D516090963EBE613ECE16924ED855487B219"
    $a12="*AC874228406D42C9AC6D92BB27F25EE541BA44DA"
    $a13="*AC874228406D42C9AC6D92BB27F25EE541BA44DA"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}