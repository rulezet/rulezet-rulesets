rule sha3_224_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4468a98fe96280279d0b3ef7ac856b628d9e937b314df7724b1c65f7"
    $a1="3da3582dd4ed112902f255253013dbd0d2709fe9df3e6fc2072e98e2"
    $a2="b007c02d625965d6115fb4aa268f2b2e4196b4fb521959b8e392a76a"
    $a3="8b9d42039f175bec40f1abc6354e7da32e29d7205437f2d4428c56f0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}