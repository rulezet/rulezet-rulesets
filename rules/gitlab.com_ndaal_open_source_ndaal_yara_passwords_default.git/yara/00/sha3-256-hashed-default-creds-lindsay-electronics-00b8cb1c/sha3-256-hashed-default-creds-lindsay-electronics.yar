rule sha3_256_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
    $a1="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a2="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
    $a3="ed4c35971eb7f4040ab02568140708eb217c91988c3edb8d4d737547e82890fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}