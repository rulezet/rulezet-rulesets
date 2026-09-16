rule sha3_256_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a1="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a2="8f2ae62f783a1c66d89c855ccf543a0d6d7bdd7aecac2faf6140b25c9477240b"
    $a3="8f2ae62f783a1c66d89c855ccf543a0d6d7bdd7aecac2faf6140b25c9477240b"
    $a4="7ddb640823a60533cb13ac0a9f15f88b79d32c274bee9e8821ed7e1333ad71cc"
    $a5="7ddb640823a60533cb13ac0a9f15f88b79d32c274bee9e8821ed7e1333ad71cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}