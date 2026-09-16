rule sha3_512_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6ff7178d9d9dcd07a656415a8866c798d259e54a8dd3b46770fc23608c20667a74ed4c2918e4e86f23851c72bacc95eef1705d0a9939d657cf091e25e7b7af5"
    $a1="ccc1420b92cc69530f013b124c71d724e95f964ad1860b8b189f8f9c7dbd0e0a98df4ffb36afe67ccb6c1d292decaa4482fd3180deb950aca89b58f27ab12a56"
condition:
    ($a0 and $a1)
}