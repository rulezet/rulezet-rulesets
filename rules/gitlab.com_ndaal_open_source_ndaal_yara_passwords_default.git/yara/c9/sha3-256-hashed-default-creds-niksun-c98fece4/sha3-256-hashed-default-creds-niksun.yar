rule sha3_256_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43a65721c3317dddf29a2afd46049330f18cd4d660f27421b447e85cf56228d5"
    $a1="009da20536b14ddcecb05c30a819f51db52ad4e1cef1e8b3f60180138fa85cb5"
condition:
    ($a0 and $a1)
}