rule sha1_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="e77916fe706d75a5882e6293b4cf4be1c7dbf485"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="baaa67aa012007d1b2d1471e58b719c8a6cef2da"
    $a9="16ceb8836feebbab3899497f31895cc37fafc9a5"
    $a10="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="e1a47a982f7b7c93e365f3018a55e536e865ee58"
    $a13="e1a47a982f7b7c93e365f3018a55e536e865ee58"
    $a14="97ba94ac2ca62ad94e39e0f4f6451241d1d2bb0b"
    $a15="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a16="95446276cdfaff3a03a22be6ad6085e6f712c004"
    $a17="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a18="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a19="d72bfa817fda0df86c5c5bb918cec57abb30172e"
    $a20="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a21="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}