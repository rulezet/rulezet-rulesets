rule md5_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="827ccb0eea8a706c4c34a16891f84e7b"
    $a1="ea79b5714b6e076bb4b00dc2879abdd7"
    $a2="827ccb0eea8a706c4c34a16891f84e7b"
    $a3="d6d9172da07e6c44c1fbcb571fd0a8f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}