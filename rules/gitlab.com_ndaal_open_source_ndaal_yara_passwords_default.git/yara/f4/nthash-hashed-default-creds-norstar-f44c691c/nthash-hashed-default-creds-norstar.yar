rule nthash_hashed_default_creds_norstar
{
    meta:
        id = "5BTkh1dYKDWG6PnxdEekAO"
        fingerprint = "b84842f461818dab6016233ddc2eeda0f533230bbaeeb9adacfaa2f61d321d50"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63506c31c665cb26144df952a4f539b4"
    $a1="f3a75adb05641dd297fcb5ce2b83f606"
    $a2="7babeb7a3a0e44a5556cb99c498844e6"
    $a3="77ecf8a802e3ce8274b51870f0ee2f6e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}