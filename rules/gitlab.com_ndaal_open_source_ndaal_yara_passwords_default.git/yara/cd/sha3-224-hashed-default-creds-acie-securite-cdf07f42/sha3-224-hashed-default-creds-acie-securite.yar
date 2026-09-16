rule sha3_224_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
    $a2="66c6da46f681e332ed21563416ae6f05b33a487bab4c68447faea72b"
    $a3="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
    $a4="bfd43f4ca512731d8486e73f71815fee4bb5ce68818e81d7f2c322fd"
    $a5="b3e393a76b984e4041c1cf22ac250954d6bc418fd2289e14cbca299b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}