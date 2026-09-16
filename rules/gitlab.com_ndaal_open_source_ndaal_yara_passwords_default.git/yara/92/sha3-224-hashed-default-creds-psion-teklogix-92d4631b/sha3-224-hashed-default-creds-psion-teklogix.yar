rule sha3_224_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f56b9ec2386e48a5f1a1d4558ab54eabb28067caf56a1568937cf833"
    $a1="6e1ff225333ba37a13cbdb7ef72b8975a5e2e296698c06ea0fe65091"
condition:
    ($a0 and $a1)
}