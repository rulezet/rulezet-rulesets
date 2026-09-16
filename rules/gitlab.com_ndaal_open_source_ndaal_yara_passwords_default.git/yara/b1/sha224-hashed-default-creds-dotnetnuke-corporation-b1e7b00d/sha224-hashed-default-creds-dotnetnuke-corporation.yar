rule sha224_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14c4b1c76b7626d2f3edb1001fb4ca6b435788d0cee8093f297caa7b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="f013b1eadd0f30bb1098f1f0d6a3a85e8580d4d1c74c67631af8977a"
    $a3="7c101be7cc7ede3574e285c9ab5c9509a82fc0397b8124c1fedd4220"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}