rule ldap_md5_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a1="{MD5}DtMBe5EZIOrlFOEqVqyY2Q=="
    $a2="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a3="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a4="{MD5}Dmj3U7xgH12dBHF/lQQnYg=="
    $a5="{MD5}VdWYtBdHjZ42kok1Q36v5w=="
    $a6="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a7="{MD5}M267sheb6qc0Ck8WIPOvQA=="
    $a8="{MD5}y96uss9bgSxiiyMlvMTFYA=="
    $a9="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
    $a10="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
    $a11="{MD5}kT+cSdy1ROIIfO4oT0oAtw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}