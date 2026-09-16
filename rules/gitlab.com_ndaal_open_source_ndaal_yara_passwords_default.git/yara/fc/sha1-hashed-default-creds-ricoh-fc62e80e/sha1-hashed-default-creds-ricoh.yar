rule sha1_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="a159b7ae81ba3552af61e9731b20870515944538"
    $a4="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a5="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}