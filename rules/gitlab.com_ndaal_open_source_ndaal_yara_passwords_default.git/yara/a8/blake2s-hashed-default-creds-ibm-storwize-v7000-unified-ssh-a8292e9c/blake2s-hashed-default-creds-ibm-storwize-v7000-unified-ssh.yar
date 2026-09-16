rule blake2s_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b39b9ec42b286d3089ee1a9d3cd032b70008eb8efe57351e96129cfc1bc2d8aa"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="2b3e97675aeca50cd4e00252abc5d8cb734540cd86db41fd5ff99d2e37275575"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="0da254bc3667d03941a3095a2256300c4b25089720d4a324e02843c22fecdde4"
    $a5="2538fd118f310b61a135cfbefc4524bfc4860d075ad19c7a9f1ba86dca1913ae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}