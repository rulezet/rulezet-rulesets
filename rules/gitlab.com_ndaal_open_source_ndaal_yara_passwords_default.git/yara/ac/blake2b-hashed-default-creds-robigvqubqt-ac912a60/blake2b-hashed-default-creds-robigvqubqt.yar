rule blake2b_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d148ef11fc7e2043dfa1cf3817a0726cfef45a098f945586675bf08baec4c472d0eaa5ffda4c10bf17fa9883da8be8d2dcbdfb7da0d0a02070af102297e7b9e"
    $a1="d33e214aabda53dff8b60e60ce872cb8c1698a0122208db57ea182f23c24c241400c95aa587844a313aae0a28f92d106092237b052991acc17f86818cba20590"
condition:
    ($a0 and $a1)
}