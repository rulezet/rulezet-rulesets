rule sha224_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e3b7cf16b9d701dd4dd4536095731b1ccff0e9a5a00a68a7ec30f00"
    $a1="5e3b7cf16b9d701dd4dd4536095731b1ccff0e9a5a00a68a7ec30f00"
condition:
    ($a0 and $a1)
}