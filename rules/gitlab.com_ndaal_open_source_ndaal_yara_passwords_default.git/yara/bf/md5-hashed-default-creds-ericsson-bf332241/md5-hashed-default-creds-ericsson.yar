rule md5_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d851b18c1313c76b2731fb1bca53af8"
    $a1="0d851b18c1313c76b2731fb1bca53af8"
    $a2="c21f969b5f03d33d43e04f8f136e7682"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="657f8b8da628ef83cf69101b6817150a"
    $a5="69090e1aa8f5397ab41bef9074816cc8"
    $a6="b9b83bad6bd2b4f7c40109304cf580e1"
    $a7="b9b83bad6bd2b4f7c40109304cf580e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}