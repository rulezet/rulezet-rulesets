rule sha3_224_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5856d58581f0e857343927170bc029c747a79e64b1dcfcc66e4bfed0"
    $a1="748ba8e5f604c11ec9c165103584328b3196753804e8f644bfeb684f"
    $a2="80782e138450cff5f0eb06091957d6d3ecc81f3a391d0be77028f0c6"
    $a3="748ba8e5f604c11ec9c165103584328b3196753804e8f644bfeb684f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}