rule sha1_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58b4d4582dd9851dc9f34afe6658b5505d05f94a"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="58b4d4582dd9851dc9f34afe6658b5505d05f94a"
    $a3="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a4="fb410b18aa82cff808971e1f95d2be15deeea2bc"
    $a5="0e3d61a44eb62e0b2ece80d057e826e01b19a484"
    $a6="fb410b18aa82cff808971e1f95d2be15deeea2bc"
    $a7="08a33a9f8c0153d526f7a13488638169d96e6b63"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}