rule blake2b_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40fc9a6b8899f9cac60ac8625073e1e38d9b9b28808d890895b51c33f663b2522117d5f7232351f479ee0c8ee2c672762e6bd05f3e94641b8060b73609c6b4ef"
    $a1="1985408c56f9a09d04c375c25450a08912e2c572964e7b4ec3f9c15caac00d7a56ddbc494bdcf0c9acc68d56e8a8cd0cbe0869d5c31abecfc209c75b35143943"
    $a2="40fc9a6b8899f9cac60ac8625073e1e38d9b9b28808d890895b51c33f663b2522117d5f7232351f479ee0c8ee2c672762e6bd05f3e94641b8060b73609c6b4ef"
    $a3="b64c0d850b7740d926f4c4ed9d58d29a72ae928e52b0962134b0e246a54f6793b9b0a4e285c6089795271a028015c2bc0ab4868b2e9b7ee522e7aa0eeb610613"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}