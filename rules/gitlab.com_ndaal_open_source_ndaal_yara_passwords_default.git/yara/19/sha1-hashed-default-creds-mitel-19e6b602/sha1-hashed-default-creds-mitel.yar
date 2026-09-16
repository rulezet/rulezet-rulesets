rule sha1_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a2="e3cbba8883fe746c6e35783c9404b4bc0c7ee9eb"
    $a3="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a4="a4b542ed3c9cfc6fd0c9eb713a2c0fdf46f582b6"
    $a5="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a6="4bafaf961d8a793ebecb1580eb84927cfe9e356c"
    $a7="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a8="5bb69f75d216c3768ea45541f47ff1fdd4c2f677"
    $a9="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a10="1a9b9508b6003b68ddfe03a9c8cbc4bd4388339b"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}