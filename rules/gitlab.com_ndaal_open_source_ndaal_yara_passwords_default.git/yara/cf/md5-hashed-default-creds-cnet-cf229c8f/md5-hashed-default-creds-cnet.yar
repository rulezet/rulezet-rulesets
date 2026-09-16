rule md5_hashed_default_creds_cnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cnet."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="697efa94ad1e665c4d0edd4c810db6fb"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="e3afed0047b08059d0fada10f400c1e5"
    $a6="697efa94ad1e665c4d0edd4c810db6fb"
    $a7="e3afed0047b08059d0fada10f400c1e5"
    $a8="5f4dcc3b5aa765d61d8327deb882cf99"
    $a9="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}