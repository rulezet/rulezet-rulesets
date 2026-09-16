rule blake2s_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c53f35af18c515119fbc42364b0f9b2e9ddefc8f861182b28d3c8457eac5f9bb"
    $a1="c53f35af18c515119fbc42364b0f9b2e9ddefc8f861182b28d3c8457eac5f9bb"
    $a2="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a3="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a4="f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
    $a5="f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}