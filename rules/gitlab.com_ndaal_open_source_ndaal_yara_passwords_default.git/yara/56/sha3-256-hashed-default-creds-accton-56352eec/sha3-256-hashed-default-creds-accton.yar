rule sha3_256_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a1="97418e93d514bfe7a5e1ffb7fbfa520340db0ae37a8238c1b4c4e9ec13fbff51"
    $a2="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a3="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}