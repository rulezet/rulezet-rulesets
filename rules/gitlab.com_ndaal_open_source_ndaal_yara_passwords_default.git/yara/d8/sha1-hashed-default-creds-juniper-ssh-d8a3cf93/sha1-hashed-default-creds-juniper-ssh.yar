rule sha1_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6367c48dd193d56ea7b0baad25b19455e529f5ee"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="a2c50c8c74330c5b54ea0b61e6fbfeea207f639a"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a7="82579efda5bd6ce6047b0903ffa462f2c1e1da65"
    $a8="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a9="25878cbc384641c1d5cf52ff89358495bb34e65c"
    $a10="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a11="e5cfb68ab0067618655b00c68d873363fe12b723"
    $a12="d6c5389f22de5dbb33df723a3309b4273a9d2ce7"
    $a13="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}