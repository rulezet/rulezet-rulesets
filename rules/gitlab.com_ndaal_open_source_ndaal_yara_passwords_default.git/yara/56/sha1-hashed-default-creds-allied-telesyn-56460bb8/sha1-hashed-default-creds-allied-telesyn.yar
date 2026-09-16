rule sha1_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a1="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a4="e69867ca7d5a7b0ab60a2a61e7b791c106f7bf64"
    $a5="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a6="e69867ca7d5a7b0ab60a2a61e7b791c106f7bf64"
    $a7="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a8="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
    $a9="af8e3e004fd2ba1abffd283d4440fd5e9f738a07"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}