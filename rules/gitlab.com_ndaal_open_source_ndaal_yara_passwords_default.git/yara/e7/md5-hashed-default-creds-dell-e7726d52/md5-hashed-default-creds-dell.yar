rule md5_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6e66b8981c1030d5650da159e79539a"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="16b0cd7f26bfb63da5eda870c941cbbd"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="d3a9194c76fbc114d0ae11515ba4f325"
    $a9="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a10="28205a1a2d93927fb5837d3a48829ef7"
    $a11="9b93a196ac81d5582c7822fbf85b1b25"
    $a12="e27c247993eda966a30472b956aeffbf"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="78d1e470dd2a43d9ff4eecd93bf9ba8d"
    $a15="c6a33911cc53df9bdb84aac8d86a0565"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}