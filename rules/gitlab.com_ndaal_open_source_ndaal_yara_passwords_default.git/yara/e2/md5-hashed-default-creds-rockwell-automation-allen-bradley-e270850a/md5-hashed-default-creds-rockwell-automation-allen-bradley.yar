rule md5_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="78946ffb0e3fd7ef4e0fece942f65759"
    $a5="764de9f0293d3b22dc80afe67679fbb3"
    $a6="78946ffb0e3fd7ef4e0fece942f65759"
    $a7="8dec700da73e02c404a484b16d4caad2"
    $a8="084e0343a0486ff05530df6c705c8bb4"
    $a9="084e0343a0486ff05530df6c705c8bb4"
    $a10="dcf87f33ba4f876cef7681c17705b490"
    $a11="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a12="129ae2db0b0ff058b9d18eaa47f33baa"
    $a13="200ceb26807d6bf99fd6f4f0d1ca54d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}