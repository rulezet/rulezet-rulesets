rule md5_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e27c247993eda966a30472b956aeffbf"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="78d1e470dd2a43d9ff4eecd93bf9ba8d"
    $a3="c6a33911cc53df9bdb84aac8d86a0565"
    $a4="28205a1a2d93927fb5837d3a48829ef7"
    $a5="9b93a196ac81d5582c7822fbf85b1b25"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}