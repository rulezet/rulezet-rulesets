rule sha3_384_hashed_default_creds_acc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a1="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
condition:
    ($a0 and $a1)
}