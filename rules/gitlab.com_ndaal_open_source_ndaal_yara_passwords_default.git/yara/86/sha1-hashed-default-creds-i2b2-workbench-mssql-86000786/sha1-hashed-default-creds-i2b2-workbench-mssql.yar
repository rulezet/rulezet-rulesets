rule sha1_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1d6ccf7a2b3167b1db2558e52575106bac5a6a"
    $a1="7cd0a50ef6014879cfe6c6ebae160fee53b33ffd"
    $a2="b7831f202ee6c562b8373e4cd397bd112c1a1f06"
    $a3="0a7fc5876bb1406f4eb4c9259f9edd9c330a6273"
    $a4="f5c83f7939640ad4dc0b67e858bb1b2aca5ee349"
    $a5="b1803660b09be47086d05904f15c2da0a16a220d"
    $a6="a32617d31c27f297ffdc94a0598137495f83b5be"
    $a7="9160017d7861851d9526cc775b3a4f2c039c9d04"
    $a8="43bff6d5cd88da01bc70466d4875a65eafac2b69"
    $a9="d9884b80682cc7dc3a79d4eca0b6f098a48d3091"
    $a10="e3d61c7d16cfab2980deefd04fecfaebd141723e"
    $a11="ccda840902275a9c7ee8c1c6a179d11e75dece26"
    $a12="69d76e9b02d0abe85fc63e658a5c481f5075bc12"
    $a13="b00dcb2894d18b9a791595e3167ade9bfae473c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}