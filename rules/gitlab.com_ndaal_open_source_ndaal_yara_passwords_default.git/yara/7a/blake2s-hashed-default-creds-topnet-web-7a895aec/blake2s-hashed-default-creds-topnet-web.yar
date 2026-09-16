rule blake2s_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68a5d0346f0f4b06ff6db7eeba6092049e4f8d5b58dd4d444c4aa9d2fdac733a"
    $a1="68a5d0346f0f4b06ff6db7eeba6092049e4f8d5b58dd4d444c4aa9d2fdac733a"
condition:
    ($a0 and $a1)
}