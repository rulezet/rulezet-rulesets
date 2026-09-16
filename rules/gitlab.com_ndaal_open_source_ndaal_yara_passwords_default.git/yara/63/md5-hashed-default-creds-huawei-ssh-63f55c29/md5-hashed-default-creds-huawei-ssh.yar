rule md5_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="e3afed0047b08059d0fada10f400c1e5"
    $a4="62b9603582c02b025d479e91b00ed397"
    $a5="62b9603582c02b025d479e91b00ed397"
    $a6="a016b28a2669f876cc24e9b3dac1bd73"
    $a7="2cc43538e62cc90345e155922056a1b3"
    $a8="1d20a3f049ad11f799bd5cf2f6a2b541"
    $a9="ee11cbb19052e40b07aac0ca060c23ee"
    $a10="ee11cbb19052e40b07aac0ca060c23ee"
    $a11="ee11cbb19052e40b07aac0ca060c23ee"
    $a12="84bc7eaa45ea2645f030a98e7866f34c"
    $a13="84bc7eaa45ea2645f030a98e7866f34c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}