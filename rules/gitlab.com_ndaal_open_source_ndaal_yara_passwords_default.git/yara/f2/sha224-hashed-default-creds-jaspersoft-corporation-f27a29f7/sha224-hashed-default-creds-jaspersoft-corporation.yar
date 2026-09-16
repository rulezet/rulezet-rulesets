rule sha224_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a1="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a2="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a3="3a94f0a636b4a3f7eeb1242137904293f054a0038b12321675543356"
    $a4="8ad7062b79554042a6442a3733d44b459974fe59e8dd1e4a13fee0bc"
    $a5="8ad7062b79554042a6442a3733d44b459974fe59e8dd1e4a13fee0bc"
    $a6="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
    $a7="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}