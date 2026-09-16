rule md5_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a36d6ecf13388e1e5419591c1d0887e9"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="d992bb8deb721e5a032ce41231fb02cc"
    $a3="d992bb8deb721e5a032ce41231fb02cc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}