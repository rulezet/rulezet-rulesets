rule sha3_224_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
    $a1="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a2="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
    $a3="6523c998bdc14a585710a887e23598933e5a63405a49f45466f662b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}