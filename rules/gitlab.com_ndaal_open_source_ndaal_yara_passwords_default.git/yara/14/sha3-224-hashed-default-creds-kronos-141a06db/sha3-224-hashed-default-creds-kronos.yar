rule sha3_224_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53ab274a32f70d8f7ee043b690d2144eedb9e386b55eb1563e60d02b"
    $a1="35f46e003490b83903fd8165aa0a7e8881bb1cbca226c511a0dfc0b6"
condition:
    ($a0 and $a1)
}