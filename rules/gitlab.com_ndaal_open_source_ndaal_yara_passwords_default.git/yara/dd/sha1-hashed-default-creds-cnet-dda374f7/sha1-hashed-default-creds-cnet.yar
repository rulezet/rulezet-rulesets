rule sha1_hashed_default_creds_cnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cnet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a6="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a7="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a8="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}