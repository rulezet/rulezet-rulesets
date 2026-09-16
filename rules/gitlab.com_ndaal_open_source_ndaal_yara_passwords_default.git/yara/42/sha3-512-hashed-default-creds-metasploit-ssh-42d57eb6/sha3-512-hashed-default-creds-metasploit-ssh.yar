rule sha3_512_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a482141f68d8c26f44c3fd81248859a6298f549fb5ce47c1fe72662b6563a4bd853a7826f4869542c933b3dea4d178cecdf8795d23dbc85aa07b8e559a005a7"
    $a1="0a482141f68d8c26f44c3fd81248859a6298f549fb5ce47c1fe72662b6563a4bd853a7826f4869542c933b3dea4d178cecdf8795d23dbc85aa07b8e559a005a7"
    $a2="75d573a7edd57cff1449898f5ac72b14312651a7be4fd685997d450a0846ea7d0ec9df7aca6e769cd8a0cc97b044903c14c715e8ad1c72d43ad7741935cadcef"
    $a3="75d573a7edd57cff1449898f5ac72b14312651a7be4fd685997d450a0846ea7d0ec9df7aca6e769cd8a0cc97b044903c14c715e8ad1c72d43ad7741935cadcef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}