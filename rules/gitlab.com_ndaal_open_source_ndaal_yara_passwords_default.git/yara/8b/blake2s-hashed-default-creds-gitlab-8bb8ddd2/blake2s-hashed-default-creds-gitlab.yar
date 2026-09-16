rule blake2s_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a3="34f8088efcdb01c2ad09b5ddf0dab2db7815dcd85e41f470d6cd67643cfb7104"
    $a4="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}