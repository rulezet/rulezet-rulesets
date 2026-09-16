rule sha3_224_hashed_default_creds_open_xchange_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9817fd4e8ae39d6e41532989e4422c5a7e46411dab4d2fdfa2270dad"
    $a1="f975d3a3780115c7fd6353e66abb77a17da423ff28d46c2297a5a8d0"
condition:
    ($a0 and $a1)
}