rule md5_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87c225cf0ef858082c1e638eae0cce66"
    $a1="87c225cf0ef858082c1e638eae0cce66"
    $a2="bc8b809f55c474463d2fb05f83792532"
    $a3="87c225cf0ef858082c1e638eae0cce66"
    $a4="cb1f1e0df36fe239ad2a8ae628a914f1"
    $a5="87c225cf0ef858082c1e638eae0cce66"
    $a6="87c225cf0ef858082c1e638eae0cce66"
    $a7="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a8="bc8b809f55c474463d2fb05f83792532"
    $a9="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a10="cb1f1e0df36fe239ad2a8ae628a914f1"
    $a11="c12e01f2a13ff5587e1e9e4aedb8242d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}