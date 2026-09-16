rule sha1_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="710f3b3c8949ca25d9ab76ceee8e54a748fa60b7"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="871fdc5e166e8bd3e100bb5108005069c20ee1d4"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="f78ad3c2b9728c4006dc37691ef9c7bf92162034"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="131969df8bc6efccb9bc84a648d202556c451eeb"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="fe7f1a1d74d8dad0095c4e921a2af2c280ebc0aa"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}