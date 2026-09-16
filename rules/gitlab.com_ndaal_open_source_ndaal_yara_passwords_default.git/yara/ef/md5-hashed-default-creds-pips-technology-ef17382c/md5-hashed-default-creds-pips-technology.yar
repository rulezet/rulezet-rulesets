rule md5_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ea65f0890df941b84e34aa82e5c6b4b"
    $a1="8ea65f0890df941b84e34aa82e5c6b4b"
    $a2="d8fd3221d8c0282917a5be7b2fe26f0c"
    $a3="d8fd3221d8c0282917a5be7b2fe26f0c"
    $a4="1c644976957bad79cbf5045b55e82231"
    $a5="1c644976957bad79cbf5045b55e82231"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}