rule blake2b_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97a53718a17fdb5b4e4a3dcaa3300cfdca331dd1b3fa04fc6dced904d8f143a6eff758f6dbbb358e73cadb956399f11242a83030a06a184f4efd0c36804b1c4b"
    $a1="8683acf26a7d208a18d9ec55625c6e3f6daf8479017225334bf03bbb2b3995ce2f50d576611c280358f9e3c9028aba2a47150bdda260b2587c14c2deb59ccfb2"
condition:
    ($a0 and $a1)
}