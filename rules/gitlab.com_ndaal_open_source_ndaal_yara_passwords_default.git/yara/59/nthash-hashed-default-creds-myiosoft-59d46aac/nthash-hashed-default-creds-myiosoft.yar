rule nthash_hashed_default_creds_myiosoft
{
    meta:
        id = "2R9myz9PYGloXSTTZMv16u"
        fingerprint = "24dbd9560355fa04ce081b6736e419fb6ffb0ddb8905c90b1b2886ad6f711f85"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a1="527c9c819b286efb8ec4ebb5b5ae71cf"
condition:
    ($a0 and $a1)
}