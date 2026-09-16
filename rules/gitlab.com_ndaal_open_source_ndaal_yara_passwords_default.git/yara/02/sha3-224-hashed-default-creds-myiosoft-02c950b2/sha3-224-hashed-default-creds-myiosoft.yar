rule sha3_224_hashed_default_creds_myiosoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a1="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
condition:
    ($a0 and $a1)
}