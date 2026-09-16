rule nthash_hashed_default_creds_openhab
{
    meta:
        id = "oIk8SgAb1oTxCFWSabS2k"
        fingerprint = "faa0eaeec4db667329e192018da972ab140799331687db89d18d21c3e3dd2726"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bfbe9bdb567187fdee1fbfcb5088ba3"
    $a1="0bfbe9bdb567187fdee1fbfcb5088ba3"
    $a2="e0bb356fd23ad715e6b55e10d3b85a4c"
    $a3="0a366241203a050268c2d8aa77fd0518"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}