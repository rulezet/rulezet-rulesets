rule md5_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08b5411f848a2581a41672a759c87380"
    $a1="08b5411f848a2581a41672a759c87380"
    $a2="0baea2f0ae20150db78f58cddac442a9"
    $a3="0baea2f0ae20150db78f58cddac442a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}