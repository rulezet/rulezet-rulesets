rule sha1_hashed_default_creds_qlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for qlogic."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="19f49d852660fe0a079cbf95c3efb34ba88de911"
    $a3="19f49d852660fe0a079cbf95c3efb34ba88de911"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}