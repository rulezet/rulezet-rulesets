rule mysql323_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="767559eb0d8d12a6"
    $a1="643a4d2911b4850c"
    $a2="70b6d1d27ed97af7"
    $a3="643a4d2911b4850c"
    $a4="099b1815176901f4"
    $a5="7a7eeba37575fe5e"
    $a6="43e9a4ab75570f5b"
    $a7="43e9a4ab75570f5b"
    $a8="767559eb0d8d12a6"
    $a9="643a4d2911b4850c"
    $a10="767559eb0d8d12a6"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}