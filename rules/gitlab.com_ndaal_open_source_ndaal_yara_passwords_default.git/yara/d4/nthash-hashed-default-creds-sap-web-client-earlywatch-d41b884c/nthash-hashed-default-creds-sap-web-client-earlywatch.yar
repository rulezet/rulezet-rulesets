rule nthash_hashed_default_creds_sap_web_client_earlywatch
{
    meta:
        id = "2uo1gmogZNaANnsgxKjgpZ"
        fingerprint = "e073776fa327b5486a2bd802fda21ed045c1f4bc7f99f2fbe7753a1da7ced52b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sap_web_client_earlywatch."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f72d8ba586179e9a0cb446e9f5d3b0fb"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}