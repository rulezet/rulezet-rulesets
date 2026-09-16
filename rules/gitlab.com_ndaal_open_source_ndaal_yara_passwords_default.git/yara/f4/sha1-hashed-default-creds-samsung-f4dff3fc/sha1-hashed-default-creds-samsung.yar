rule sha1_hashed_default_creds_samsung
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d985ae85c5bab650b3354f63c9d70d1767d48ef"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a3="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="9dae2fef0a3060734b996196e72e2730d00525b9"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}