rule mysql323_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="6a77f1277b51f67f"
    $a2="45e7b2790e3769f5"
    $a3="109be9900d0cfff2"
    $a4="1c26b9ae492e1421"
    $a5="6a77f1277b51f67f"
    $a6="45e7b2790e3769f5"
    $a7="109be9900d0cfff2"
    $a8="5d2e19393cc5ef67"
    $a9="6a77f1277b51f67f"
    $a10="465ff47d58c823ca"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}