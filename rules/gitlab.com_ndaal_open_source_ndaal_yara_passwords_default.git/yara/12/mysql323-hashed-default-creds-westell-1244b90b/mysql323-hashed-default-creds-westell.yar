rule mysql323_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7337f77a739e7fe1"
    $a1="43e9a4ab75570f5b"
    $a2="7833f50c0e8b7422"
    $a3="73fe752b0b01e8ed"
    $a4="360544de4421f292"
    $a5="43e9a4ab75570f5b"
    $a6="5d2e19393cc5ef67"
    $a7="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}