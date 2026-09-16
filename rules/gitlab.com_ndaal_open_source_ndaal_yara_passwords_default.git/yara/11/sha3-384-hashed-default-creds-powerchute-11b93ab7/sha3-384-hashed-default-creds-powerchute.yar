rule sha3_384_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6f93b8be89cba6d606a191f69b5cec489dddeccc706583c6fc74e580e86e055c784e8c01993302fbccb8b0c65548f30"
    $a1="e6f93b8be89cba6d606a191f69b5cec489dddeccc706583c6fc74e580e86e055c784e8c01993302fbccb8b0c65548f30"
condition:
    ($a0 and $a1)
}