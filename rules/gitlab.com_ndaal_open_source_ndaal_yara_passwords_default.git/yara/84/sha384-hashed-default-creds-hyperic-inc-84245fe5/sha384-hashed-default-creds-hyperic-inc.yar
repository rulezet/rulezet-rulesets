rule sha384_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f82902fb8460f054e8275b3cc7197e3ccf98dcb8553844964033d2b2655bbfe8fa3f0ed7492b128d1adb699f422909c7"
    $a1="f82902fb8460f054e8275b3cc7197e3ccf98dcb8553844964033d2b2655bbfe8fa3f0ed7492b128d1adb699f422909c7"
condition:
    ($a0 and $a1)
}