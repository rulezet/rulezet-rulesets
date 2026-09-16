rule sha512_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e83b7fe1803c622124721a2e4643172a45874fd040092eaf92abb28f2a3b043c8ceabeb78679994fc15413412742ff9979d97e31d7241d81a9bfbb21b3dcad8"
    $a1="4e83b7fe1803c622124721a2e4643172a45874fd040092eaf92abb28f2a3b043c8ceabeb78679994fc15413412742ff9979d97e31d7241d81a9bfbb21b3dcad8"
condition:
    ($a0 and $a1)
}