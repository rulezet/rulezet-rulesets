rule sha1_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a2="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a5="3559bce6266259c61c0e8aa43f5d209198f516e1"
    $a6="d8e0e4bc172f47394f71c6c431475ec37b883c4d"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="18d9f6a3fa5a99fee0cf9705f7daad435621071f"
    $a9="9a198c9f036b7383995bfa3e3051ecffb506fd95"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}