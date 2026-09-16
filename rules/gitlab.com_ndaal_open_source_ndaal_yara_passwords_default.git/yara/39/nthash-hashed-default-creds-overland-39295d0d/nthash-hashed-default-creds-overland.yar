rule nthash_hashed_default_creds_overland
{
    meta:
        id = "2tquNZg0W7XCIKDxbouMSH"
        fingerprint = "bf3787048a97211d43c5d767931662a99f9f412000d857c6fc174a2a2cfe7a46"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="880aa8beaef65966121e8d79ed8b42a6"
    $a1="d94dcf92d61d9df33f60a402b4d61755"
condition:
    ($a0 and $a1)
}