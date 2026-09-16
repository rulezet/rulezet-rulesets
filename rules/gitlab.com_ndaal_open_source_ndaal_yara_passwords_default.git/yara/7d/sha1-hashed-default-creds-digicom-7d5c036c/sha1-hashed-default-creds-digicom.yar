rule sha1_hashed_default_creds_digicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="018231af746bda59ff2c0d1c20f9dd6a95b16f06"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}