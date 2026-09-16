rule md5_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="154a3745a2a919c100a73a7f2303ef18"
    $a1="c1b21f4648771c46acb6ac65b762b3f4"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="697efa94ad1e665c4d0edd4c810db6fb"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="97876d07ec3d609a6edc5871f03a3ca3"
    $a7="97876d07ec3d609a6edc5871f03a3ca3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}