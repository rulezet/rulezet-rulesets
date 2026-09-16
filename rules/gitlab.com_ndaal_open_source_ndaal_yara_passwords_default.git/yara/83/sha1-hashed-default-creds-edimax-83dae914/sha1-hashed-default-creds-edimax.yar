rule sha1_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="40bd001563085fc35165329ea1ff5c5ecbdbbeef"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="3cf458d745f6ab044b5664382678629b3c08484a"
    $a7="bab68a3e6115a7b252c5b67d438f3302a352e16d"
    $a8="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="3c711462f7487c8705d7a359f1fb9d8f179518c5"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a13="35675e68f4b5af7b995d9205ad0fc43842f16450"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}