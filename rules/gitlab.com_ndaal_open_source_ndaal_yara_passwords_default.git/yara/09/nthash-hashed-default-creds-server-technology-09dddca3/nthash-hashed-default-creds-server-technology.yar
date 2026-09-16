rule nthash_hashed_default_creds_server_technology
{
    meta:
        id = "7TMs5CPimzbV0JpwFVz1CR"
        fingerprint = "32c00a88485029644ee2d6332b9e0857a76ee856b6f38fc515b31a39c9b474fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca10ea058b7d57acc3937e1d99b5904"
    $a1="31bd38262627adb669467fb8325bb7e6"
    $a2="607d3f443fc91de577819b4e9a194443"
    $a3="31dee9eb79bcd52173b906d730f29013"
    $a4="22b695e9b88ccc2ad1dacfe8d9711e03"
    $a5="24e28f60cfa2c9789568a1b2c1315e09"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}