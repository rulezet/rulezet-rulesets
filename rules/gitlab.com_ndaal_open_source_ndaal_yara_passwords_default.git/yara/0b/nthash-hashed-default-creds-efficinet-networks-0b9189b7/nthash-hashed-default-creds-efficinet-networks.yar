rule nthash_hashed_default_creds_efficinet_networks
{
    meta:
        id = "4HUU1CWmbN6gNRSiP902OM"
        fingerprint = "4db05f3073ed786a02281fe2b7024b9c1de192a8f744a7c2e7e7453c7060900e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficinet_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="e6bd4cdb1e447131b60418f31d0b81d6"
condition:
    ($a0 and $a1)
}