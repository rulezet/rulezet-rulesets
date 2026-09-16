rule sha256_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0228ba1c9fa00283cb17958ea7f601c602580fe4fa29bbb1c4c89ae4d2828cb8"
    $a1="0228ba1c9fa00283cb17958ea7f601c602580fe4fa29bbb1c4c89ae4d2828cb8"
    $a2="7b8c8ebdd4a28d34f1048da4e4916dbf0ed5771944805100ddf1b29c9509b6f6"
    $a3="7b8c8ebdd4a28d34f1048da4e4916dbf0ed5771944805100ddf1b29c9509b6f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}