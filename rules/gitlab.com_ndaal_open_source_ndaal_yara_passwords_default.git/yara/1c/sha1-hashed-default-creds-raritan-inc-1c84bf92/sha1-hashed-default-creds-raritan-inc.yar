rule sha1_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cdb64ab11d0fdb311169173c92017669556ef5e"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="9cdb64ab11d0fdb311169173c92017669556ef5e"
    $a3="8a77e1b121a26482db90e7875704d568a8bbcb83"
    $a4="30a5d8073122be0fd8b37a6fb06eb73475e50260"
    $a5="6771b92b0e068abf285efc6810117f73c0b15367"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}