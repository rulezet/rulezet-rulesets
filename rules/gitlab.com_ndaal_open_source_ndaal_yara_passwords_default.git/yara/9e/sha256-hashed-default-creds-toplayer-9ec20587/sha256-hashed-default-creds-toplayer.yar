rule sha256_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67c942383e477c55d6843d10cdde5494601c53e060966dd95a1dfd7930a74a00"
    $a1="4b4d84a924bee4381c8cba1badfe3aa96cd7746ec02e36f862fab18caf42dafc"
condition:
    ($a0 and $a1)
}