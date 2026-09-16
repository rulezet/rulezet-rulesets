rule sha224_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a344a7a157fe55175b70cb5a6867b11b680aeb6e20f8f84b988b2897"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
    $a3="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}