rule sha1_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a1="85c06b86767a2fdf918a9e307f936ab361cdc40a"
    $a2="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a3="5e95a05b5536aa820f28ead7a645bafe131ee0d1"
    $a4="986dab2caf11b97fbbf2b43e626dbea98e754ace"
    $a5="6e576d4bc16290d7f13671435742f1a0b0987de8"
    $a6="112bb791304791ddcf692e29fd5cf149b35fea37"
    $a7="688ca1ff2e3800eca1ebe3cfa9a03dd2c3ad27d2"
    $a8="329cb8b6ba8c427be7c09b298295c655415c7ac9"
    $a9="329cb8b6ba8c427be7c09b298295c655415c7ac9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}