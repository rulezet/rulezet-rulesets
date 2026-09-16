rule sha1_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77eb1db6cb81b3cb088d36ab7aae8f230dcfaa28"
    $a1="ad594f17d657ef21d59f2012f4388d8b65352d5e"
    $a2="51e822c50cc62cdbdb850a439ea75b6d45ac487b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="26f580ae0efc69079ed9a6beea0e30288ad90119"
    $a7="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a8="72944a17c06eedbdd83d6bfd8d9999e8a2236637"
    $a9="55d25800fb82ba29a267c932300aaa8a19767b75"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}