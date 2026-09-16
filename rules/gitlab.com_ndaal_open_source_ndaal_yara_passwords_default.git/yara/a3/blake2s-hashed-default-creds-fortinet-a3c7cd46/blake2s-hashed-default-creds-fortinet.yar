rule blake2s_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
    $a2="4079543c0441ed4a6949a2b2206a1adb04063089461026592addbfb04e3575b3"
    $a3="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
    $a4="ecc901026d4b7dd2f933a628c6c0dda3e5ff33ba69016cee9560ca34a29199e9"
    $a5="211cf96d140aeafb62ffc43abe3f75812fa2651cd37a15ec6d829a2b085f22cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}