rule md5_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7948414a106f87588174e97878ea8768"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ee11cbb19052e40b07aac0ca060c23ee"
    $a3="ee11cbb19052e40b07aac0ca060c23ee"
    $a4="084e0343a0486ff05530df6c705c8bb4"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="0baf78e0dcadd5125fbb6ae50514b3e7"
    $a7="ee11cbb19052e40b07aac0ca060c23ee"
    $a8="284f2b088a8d88997a293e02e980e1df"
    $a9="0b180078d994cb2b5ed89d7ce8e7eea2"
    $a10="7948414a106f87588174e97878ea8768"
    $a11="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}