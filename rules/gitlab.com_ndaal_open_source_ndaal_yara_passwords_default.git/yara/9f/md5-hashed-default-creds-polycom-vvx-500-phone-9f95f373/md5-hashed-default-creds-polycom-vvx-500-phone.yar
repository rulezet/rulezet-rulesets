rule md5_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="250cf8b51c773f3f8dc8b4be867a9a02"
    $a1="e3afed0047b08059d0fada10f400c1e5"
    $a2="202cb962ac59075b964b07152d234b70"
    $a3="8f9bfe9d1345237cb3b2b205864da075"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}