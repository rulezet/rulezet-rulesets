rule blake2s_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a1="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="6625d441eb5ccdd1bf4b25d7d79f6981dcde2d8d1f129256aab66503a8de0246"
    $a5="809fde73e58d19e607c95bd63276904d24f7be93b948ebbba6f24f8f440bfa46"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}