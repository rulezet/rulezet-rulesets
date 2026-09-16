rule sha3_384_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6dbdc356c10d30113880cde6614f1dc87ffe658f96cd1c9cdb06ca57f928fd11b72b00bb8712e7b5a9269ad37cbf02dd"
    $a1="6dbdc356c10d30113880cde6614f1dc87ffe658f96cd1c9cdb06ca57f928fd11b72b00bb8712e7b5a9269ad37cbf02dd"
condition:
    ($a0 and $a1)
}