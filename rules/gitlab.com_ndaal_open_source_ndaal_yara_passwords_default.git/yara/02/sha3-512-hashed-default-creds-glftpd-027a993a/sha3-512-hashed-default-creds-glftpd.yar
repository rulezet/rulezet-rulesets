rule sha3_512_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d98b1b5fcb844e838b3e56ed62789c5284f76be2ce82c96c827c57457dc9fd826bda545f43c6a63d4c73554b8d3386592f8d38d24f811ab26ae4de8fb8647e7"
    $a1="3d98b1b5fcb844e838b3e56ed62789c5284f76be2ce82c96c827c57457dc9fd826bda545f43c6a63d4c73554b8d3386592f8d38d24f811ab26ae4de8fb8647e7"
condition:
    ($a0 and $a1)
}