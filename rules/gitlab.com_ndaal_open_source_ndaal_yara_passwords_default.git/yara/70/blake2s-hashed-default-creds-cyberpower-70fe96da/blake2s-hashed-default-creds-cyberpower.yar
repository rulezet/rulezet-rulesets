rule blake2s_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
    $a1="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
    $a2="c45896cbe399663bcf8c3e2309194d540ca0fefab67978ca146675af45dd914d"
    $a3="f7a7eba9542ac5dd4d5abd94a46de7b8c5f09c5d530ebff4a8f698bf25487fdf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}