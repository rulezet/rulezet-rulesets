rule md5_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e13f5f57d9792d3b38d5f3795e15d0b"
    $a1="e8a48653851e28c69d0506508fb27fc5"
    $a2="ba756b3e4e93533bf0c8fafd5dab9a5c"
    $a3="e8a48653851e28c69d0506508fb27fc5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}