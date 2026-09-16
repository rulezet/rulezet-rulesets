rule mysql323_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4106d1813dcd3369"
    $a1="4524bf323ff3f9e8"
    $a2="171b786d2574fdba"
    $a3="43e9a4ab75570f5b"
    $a4="57929b7521819b9b"
    $a5="1a6d81551efb7025"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}