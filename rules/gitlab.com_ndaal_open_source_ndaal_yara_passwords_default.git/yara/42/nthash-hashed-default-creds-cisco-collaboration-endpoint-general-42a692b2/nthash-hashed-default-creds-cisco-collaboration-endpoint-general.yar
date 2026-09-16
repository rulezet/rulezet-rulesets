rule nthash_hashed_default_creds_cisco_collaboration_endpoint_general
{
    meta:
        id = "5sU5b9rCD0C1ozuZ8bgsXu"
        fingerprint = "eae9b3e884b1a09001190ebc69769811a83af0a38f153444fbe824f05d2aa03c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_collaboration_endpoint_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="5c800f13a3ce86ed2540dd4e7331e9a2"
condition:
    ($a0 and $a1)
}