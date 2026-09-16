rule nthash_hashed_default_creds_bewan
{
    meta:
        id = "1Oc9kBIG43Wg8N54zFPu8A"
        fingerprint = "6ef7a9e40f799655f230b74db4df50140246b139c9aaef199b986df75639479b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78940fe14c28d9302a34f2529ea2b673"
    $a1="78940fe14c28d9302a34f2529ea2b673"
condition:
    ($a0 and $a1)
}