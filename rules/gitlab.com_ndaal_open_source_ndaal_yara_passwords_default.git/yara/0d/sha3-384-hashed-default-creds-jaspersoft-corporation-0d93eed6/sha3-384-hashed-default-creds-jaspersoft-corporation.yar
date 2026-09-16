rule sha3_384_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a1="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a2="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a3="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a4="fb3e508804e79703e22505e60e22e2f73518aa7efac78c5cca205d3dfb17dde87b4495e2368320a1b81676d4ea3cbdec"
    $a5="fb3e508804e79703e22505e60e22e2f73518aa7efac78c5cca205d3dfb17dde87b4495e2368320a1b81676d4ea3cbdec"
    $a6="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
    $a7="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}