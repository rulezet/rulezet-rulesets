rule md5_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92eb5ffee6ae2fec3ad71c777531578f"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="0cc175b9c0f1b6a831c399e269772661"
    $a3="cc2f410031aea40769918b7adb73a696"
    $a4="92eb5ffee6ae2fec3ad71c777531578f"
    $a5="d92c25d41fcd9f8ab35545ef34b1e7ed"
    $a6="8277e0910d750195b448797616e091ad"
    $a7="6153e02bf67aa1bcfa34168d62e9da3c"
    $a8="2db95e8e1a9267b7a1188556b2013b33"
    $a9="6ecec3241b6977a6c014d9614ec7ff9b"
    $a10="6f8f57715090da2632453988d9a1501b"
    $a11="c1f1782a3d769c40484c849b8754c705"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}