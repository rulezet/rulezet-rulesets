rule sha224_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a1="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a2="c820f3b40c3efbfa79b45ed41fab1396728982b23aca5a64be2cadf0"
    $a3="c820f3b40c3efbfa79b45ed41fab1396728982b23aca5a64be2cadf0"
    $a4="ad1b07f41d112c11c5f55426149af9d6309318f989fc84ac44b34cae"
    $a5="ad1b07f41d112c11c5f55426149af9d6309318f989fc84ac44b34cae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}