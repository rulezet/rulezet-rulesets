rule sha1_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a2="40bd001563085fc35165329ea1ff5c5ecbdbbeef"
    $a3="9f8a2389a20ca0752aa9e95093515517e90e194c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}