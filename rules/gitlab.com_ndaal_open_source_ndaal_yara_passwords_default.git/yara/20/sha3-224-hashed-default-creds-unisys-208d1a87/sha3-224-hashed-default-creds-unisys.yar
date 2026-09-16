rule sha3_224_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a1="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a2="404e6d67fca63bda577d2592bf02fbd76d5658a29c2c5211bdadd16e"
    $a3="404e6d67fca63bda577d2592bf02fbd76d5658a29c2c5211bdadd16e"
    $a4="c2107b85dbf5b3b63a2f747a9a4e37aca34f254925b5b55fe5978876"
    $a5="c2107b85dbf5b3b63a2f747a9a4e37aca34f254925b5b55fe5978876"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}