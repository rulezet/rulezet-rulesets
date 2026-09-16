rule nthash_hashed_default_creds_kali_linux_os
{
    meta:
        id = "2yCeLGIwcuAspZhFJ5b4F5"
        fingerprint = "12a29dc323713a5dd130d53cbb1e8c7996d6deffca11a6d0c7e2d34a4c2d9c7a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kali_linux_os."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc9417a516bcedc3a39a05a108eda4f6"
    $a1="fc9417a516bcedc3a39a05a108eda4f6"
    $a2="afc44ee7351d61d00698796da06b1ebf"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}