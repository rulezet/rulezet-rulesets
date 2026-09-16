rule sha1_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
    $a2="3e349224dd238599c8be07b58c46c7a751e7357b"
    $a3="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
    $a4="f81ec4fe7879c9a6d06b7204417f3097d727fd6d"
    $a5="86416ef3eeb4cc907ebcd12c0305511b4cfc5474"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}