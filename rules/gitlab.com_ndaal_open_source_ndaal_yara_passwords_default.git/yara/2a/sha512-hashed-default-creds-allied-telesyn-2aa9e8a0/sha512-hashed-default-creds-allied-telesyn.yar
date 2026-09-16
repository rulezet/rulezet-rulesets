rule sha512_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a1="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a4="83004bb19c3daaf3babbeb0aa831acaf52eca126abe8d74628e22b6ec6a5741dc61680e3fc7497073911a49bf1db94196900dfe49b766aed91781f829a7f2c00"
    $a5="290cdcaab07595d41dda81be97b19b9dd2f0ccd7594268d075a9eac22121c2fb033469f384c988ed20749aa4ce0f46f5c592a9468c8609c8de1b6a5bad56b596"
    $a6="83004bb19c3daaf3babbeb0aa831acaf52eca126abe8d74628e22b6ec6a5741dc61680e3fc7497073911a49bf1db94196900dfe49b766aed91781f829a7f2c00"
    $a7="5fc2ca6f085919f2f77626f1e280fab9cc92b4edc9edc53ac6eee3f72c5c508e869ee9d67a96d63986d14c1c2b82c35ff5f31494bea831015424f59c96fff664"
    $a8="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
    $a9="ac4ff0eb7e78b66018ad6cbdd4cb8896038fec6d696b6a423b26832e75fe89f1b7e5d77d840031909e13bc8dae80f4e48116af4cd4ae965fdde672ecfdad0c6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}