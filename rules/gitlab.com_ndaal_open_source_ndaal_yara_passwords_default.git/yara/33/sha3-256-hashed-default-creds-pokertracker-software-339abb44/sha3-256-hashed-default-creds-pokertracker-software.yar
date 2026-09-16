rule sha3_256_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a6e8dd12dd477d6cc85af9ab82584e90004a76ef37472962a3e29043553f1435"
    $a1="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
    $a2="002f155fe3eda005e73e92fafa6300190c219e8198d9c0b74f325b586174e509"
    $a3="05f3199104dc45a7e93f5d1592f309403fe16d2f1bde83a2c903ddb17b0490e1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}