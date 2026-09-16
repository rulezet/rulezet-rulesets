rule blake2s_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b04fab18cc1da79a461571efa1db7ebdf0e6d7687e4af47296763a4285e7eefd"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
    $a3="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}