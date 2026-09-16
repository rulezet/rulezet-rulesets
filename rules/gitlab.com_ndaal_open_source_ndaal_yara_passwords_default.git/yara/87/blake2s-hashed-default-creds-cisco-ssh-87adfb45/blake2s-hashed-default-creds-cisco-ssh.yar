rule blake2s_hashed_default_creds_cisco_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a1="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a2="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a3="2008ddb51e6f0e192c7ba137dbd27e689f59e6ce514c31d4912f58a32b7210a6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}