rule mysql323_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76f5418b5892e8f9"
    $a1="43e9a4ab75570f5b"
    $a2="76f542465892e5b4"
    $a3="43e9a4ab75570f5b"
    $a4="7883fe324b24e75b"
    $a5="43e9a4ab75570f5b"
    $a6="79e6a91a48b3fe2c"
    $a7="43e9a4ab75570f5b"
    $a8="018d3ccd6002f30a"
    $a9="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}