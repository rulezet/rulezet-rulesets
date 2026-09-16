rule md5_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="33e1ef4a4e8d2524181fe1697f77e758"
    $a1="995f0594cc697585a7c1ab26ef3da95d"
    $a2="e25a13535c686aa3f340d88ab4e7a83c"
    $a3="995f0594cc697585a7c1ab26ef3da95d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}