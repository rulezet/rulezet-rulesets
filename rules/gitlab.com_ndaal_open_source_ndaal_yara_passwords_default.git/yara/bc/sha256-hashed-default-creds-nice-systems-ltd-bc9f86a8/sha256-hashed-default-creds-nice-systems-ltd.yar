rule sha256_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
    $a1="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a2="4aa47f0fdad5e1c87093ddde8a219a75a0b2bf41cae1ebadbf8cff51957d3339"
    $a3="4e2b25facc0e9a98c6574cab867ea6a31c7c883ad4a4865fd60cdc80fbd50e5d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}