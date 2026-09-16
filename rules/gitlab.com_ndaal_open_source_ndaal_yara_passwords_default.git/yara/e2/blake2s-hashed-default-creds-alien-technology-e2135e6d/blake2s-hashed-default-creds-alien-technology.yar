rule blake2s_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
    $a1="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
    $a2="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}