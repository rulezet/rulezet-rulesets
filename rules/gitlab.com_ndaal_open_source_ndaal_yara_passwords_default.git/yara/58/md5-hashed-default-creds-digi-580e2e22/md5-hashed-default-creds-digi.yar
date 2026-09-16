rule md5_hashed_default_creds_digi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b52c78bd30114895a1ddcb102a47185"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="14c4b06b824ec593239362517f538b29"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}