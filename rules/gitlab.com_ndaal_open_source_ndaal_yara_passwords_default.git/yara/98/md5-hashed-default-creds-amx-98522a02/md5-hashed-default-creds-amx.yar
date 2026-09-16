rule md5_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d7311ba459f9e45ed746755a32dcd11"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a4="e842795b282293fd61bc294c49edb12b"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="6c560514dcc18f9c31bfc1d5d29a7aa0"
    $a8="9d7311ba459f9e45ed746755a32dcd11"
    $a9="e3afed0047b08059d0fada10f400c1e5"
    $a10="084e0343a0486ff05530df6c705c8bb4"
    $a11="084e0343a0486ff05530df6c705c8bb4"
    $a12="21232f297a57a5a743894a0e4a801fc3"
    $a13="21232f297a57a5a743894a0e4a801fc3"
    $a14="3e95b35df14d879fefda0ccd08974446"
    $a15="7b7bc2512ee1fedcd76bdc68926d4f7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}