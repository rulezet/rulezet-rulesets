rule sha224_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="ac1474b06b6662446155ce2845692a9b1a156139b1d5464955b4f483"
    $a5="32ee436e5d71971e37541945be338f5d792aa9aa3a95a99eb7f38bad"
    $a6="ac1474b06b6662446155ce2845692a9b1a156139b1d5464955b4f483"
    $a7="5e42b4b573660aaa6783cb49625c6a2ca3fd2ceb0db836d2f55b3452"
    $a8="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a9="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a10="687cb1ae396b49a4344c96d8da99ee7dae292b03eeeba4a127ae1876"
    $a11="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a12="d39148f4d651d07e5598a70830cb4af98f5e64ebd151342e5139b828"
    $a13="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}