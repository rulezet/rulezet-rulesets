rule blake2s_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a1="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a2="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
    $a3="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
    $a4="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a5="9c5bd1b309db17692b3b62c291ebb49cf9836e2e2f901667bb8ad2584765be76"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}