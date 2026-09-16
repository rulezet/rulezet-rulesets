rule sha1_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f5e3d2e5d28ca70d09ab79714fd2c902922e563"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="78db636360cb4360195174db0b5cebb47c866e13"
    $a3="612b43627c3800e8933106b68548c29bf0bff3c3"
    $a4="170280c9aa9b636f34c02c6236390d85fda93bd3"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="0b7b05de50741ace942ca60e1d07c45a86afb8db"
    $a7="859c12ebcb4babf13a6b16e50eb4ecf726ee3803"
    $a8="1b5f8a2a5d8ab37b7fbaa63f53200aa2d7c612c6"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a10="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="86c4ec9c0f224bd80c6d7cca8537e5464f9966bf"
    $a13="ab2bff515df9ca35fc7ca87430a6c5642653e4b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}