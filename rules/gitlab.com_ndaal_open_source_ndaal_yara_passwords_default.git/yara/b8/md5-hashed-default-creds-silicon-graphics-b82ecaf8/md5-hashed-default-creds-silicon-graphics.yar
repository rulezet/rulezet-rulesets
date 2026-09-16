rule md5_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6931b735d68fc8e9aab0b1547dc0fe24"
    $a1="6931b735d68fc8e9aab0b1547dc0fe24"
    $a2="06e3d36fa30cea095545139854ad1fb9"
    $a3="06e3d36fa30cea095545139854ad1fb9"
    $a4="f0a4025b3b49b3e256004503ee31df8c"
    $a5="f0a4025b3b49b3e256004503ee31df8c"
    $a6="1f6f42334e1709a4e0f9922ad789912b"
    $a7="1f6f42334e1709a4e0f9922ad789912b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}