rule sha224_hashed_default_creds_protocraft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for protocraft."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90e84fbcb14492c42d87ebfc5dfef28b25f536fccecf4f3b21e34b56"
    $a1="18250460059f5cf002f219bdf70d720b8d7eaa2f250a8aaa56dadea9"
condition:
    ($a0 and $a1)
}