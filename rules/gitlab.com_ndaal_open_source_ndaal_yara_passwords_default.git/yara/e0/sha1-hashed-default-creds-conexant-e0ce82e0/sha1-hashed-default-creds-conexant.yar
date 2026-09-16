rule sha1_hashed_default_creds_conexant
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conexant."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="b3f94abeb9985f60ad1bf2dc959ce02f40c4a4c5"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="94f2272c586f7d9c5de438a8d8045764e2a32ceb"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}