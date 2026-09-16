rule sha3_224_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a1="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a2="744fea4d133666d8c47e336bdc16863aac16557a1ad20960d4046ec2"
    $a3="bdb11dc835753ead8a8a45b5408462e5484151f536db41b3884aede4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}