rule md5_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1c759add0bfa882387a1bc56b31e8e4"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="1b359d8753858b55befa0441067aaed3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="925ad2679b095816cfc0cf772f467229"
    $a7="29a7e96467b69a9f5a93332e29e9b0de"
    $a8="31b864b5546913dd928a49416a10bad1"
    $a9="31b864b5546913dd928a49416a10bad1"
    $a10="925ad2679b095816cfc0cf772f467229"
    $a11="63a9f0ea7bb98050796b649e85481845"
    $a12="63a9f0ea7bb98050796b649e85481845"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="925ad2679b095816cfc0cf772f467229"
    $a15="1b359d8753858b55befa0441067aaed3"
    $a16="1b359d8753858b55befa0441067aaed3"
    $a17="1b359d8753858b55befa0441067aaed3"
    $a18="1b359d8753858b55befa0441067aaed3"
    $a19="f6cb3e816496528d4187db53bc66567f"
    $a20="1b359d8753858b55befa0441067aaed3"
    $a21="31b864b5546913dd928a49416a10bad1"
    $a22="714b393f4b2c29561d44c5e0a90ffdb9"
    $a23="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}