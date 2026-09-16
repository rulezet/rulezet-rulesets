rule md5_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f222b9ec8469d27230ef4201f95e3d46"
    $a1="f222b9ec8469d27230ef4201f95e3d46"
    $a2="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a3="bba034891e3d3b8e4ddd34f5c028b7dc"
    $a4="e99a18c428cb38d5f260853678922e03"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="f222b9ec8469d27230ef4201f95e3d46"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="0ae2415b0a3d8a58ab71d9e608af351b"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a11="29f58ed4a99ee32fc64c25f9670e0f4e"
    $a12="a24f3d36f6baa87c72b521ec3fc01e2e"
    $a13="1b3231655cebb7a1f783eddf27d254ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}