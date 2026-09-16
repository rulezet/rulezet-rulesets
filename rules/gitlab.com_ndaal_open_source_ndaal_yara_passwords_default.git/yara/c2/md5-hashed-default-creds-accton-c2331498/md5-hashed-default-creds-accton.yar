rule md5_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d0258c2440a8d19e716292b231e3190"
    $a1="1d0258c2440a8d19e716292b231e3190"
    $a2="08b5411f848a2581a41672a759c87380"
    $a3="08b5411f848a2581a41672a759c87380"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}