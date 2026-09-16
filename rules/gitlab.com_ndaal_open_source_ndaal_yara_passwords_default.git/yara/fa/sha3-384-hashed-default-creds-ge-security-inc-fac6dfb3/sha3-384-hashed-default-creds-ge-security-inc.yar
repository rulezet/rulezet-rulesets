rule sha3_384_hashed_default_creds_ge_security_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge_security_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="455110feb9390dfb134779ee606f68e8b2210bdea5bdc885e4181e7afc7ee72f5cc05e83009d95bbc76318ecfec979b1"
    $a1="455110feb9390dfb134779ee606f68e8b2210bdea5bdc885e4181e7afc7ee72f5cc05e83009d95bbc76318ecfec979b1"
condition:
    ($a0 and $a1)
}