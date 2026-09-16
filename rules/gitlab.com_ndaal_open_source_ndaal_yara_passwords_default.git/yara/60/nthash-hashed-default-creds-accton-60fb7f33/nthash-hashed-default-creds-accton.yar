rule nthash_hashed_default_creds_accton
{
    meta:
        id = "7e50IYR73SYtgWPUsugXgG"
        fingerprint = "2a74b4f06a3a7cd0a07672c3477e980de7a01415fe443e4ade3e8481962f6f09"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="f938b53b982f22cd6b1c14ae10665480"
    $a2="3b6be948d1d1b370bdefe5d6c74142a6"
    $a3="3b6be948d1d1b370bdefe5d6c74142a6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}