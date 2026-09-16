rule sha1_hashed_default_creds_microcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microcom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a501f617fbcc6c2f554b375ec09d380fac3705a0"
    $a1="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a2="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}