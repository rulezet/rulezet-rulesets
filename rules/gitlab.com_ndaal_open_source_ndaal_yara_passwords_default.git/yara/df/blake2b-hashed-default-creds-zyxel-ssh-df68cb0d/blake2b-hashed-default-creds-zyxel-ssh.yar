rule blake2b_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa04814d76ce71ff41174915b0f6add1a36645683395290c98a9fea0e9b043f924b96446e22c7badadc80d46f7e4b54b1a7d70b669d024982c0ce8773461f48f"
    $a1="50ef1ff7afd840785894fe8447ab0175436d1a0ea24b8fc05b60049e6ca7242d19d8a53aaf65149f8c0ce5416d4924977dfb39f41d227b0cd01542059ec8ac77"
condition:
    ($a0 and $a1)
}