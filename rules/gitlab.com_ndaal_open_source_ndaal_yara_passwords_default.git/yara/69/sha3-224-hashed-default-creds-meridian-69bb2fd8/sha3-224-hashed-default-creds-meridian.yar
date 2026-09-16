rule sha3_224_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd9dc48ed52245c81385c2a50f69254ef2318efd51650adb441113cc"
    $a1="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
condition:
    ($a0 and $a1)
}