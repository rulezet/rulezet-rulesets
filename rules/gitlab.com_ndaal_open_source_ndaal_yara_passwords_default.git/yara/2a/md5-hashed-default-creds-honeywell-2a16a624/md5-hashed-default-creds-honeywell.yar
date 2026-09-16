rule md5_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a2="2f6ce515b22ea0f321e8b814be1f6bb0"
    $a3="1036ab2848c17d92d0433e8ce98e903a"
    $a4="23052fe3f5bc627d154d858efb40a165"
    $a5="837129fcceba19fe87e4c1244ffa0721"
    $a6="084e0343a0486ff05530df6c705c8bb4"
    $a7="adb831a7fdd83dd1e2a309ce7591dff8"
    $a8="b60eb83bf533eecf1bde65940925a981"
    $a9="a0a02c22a8a05cda7b40dce67cd6e622"
    $a10="21232f297a57a5a743894a0e4a801fc3"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}