rule blake2s_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a1="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a2="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a3="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}