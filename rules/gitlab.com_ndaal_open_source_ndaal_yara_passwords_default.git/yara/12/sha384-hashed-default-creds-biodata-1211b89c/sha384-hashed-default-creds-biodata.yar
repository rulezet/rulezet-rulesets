rule sha384_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b972b3e3836c057362f312ac377b236b70efe347eb7c36ad5810142aa459f6fcf79e3066d95b91dab6c4d507d65b4b04"
    $a1="37d7a199fa800dbef1b994f0aeaaef95504f851f594b54a5f833fe2ec755767dd9623685cc33a2860f953d7d0ef95a38"
condition:
    ($a0 and $a1)
}