rule nthash_hashed_default_creds_network_appliance
{
    meta:
        id = "4T9A5tTfbbqCS3515iXZrX"
        fingerprint = "91cf6f2cd3ec6b59df32b3515d0d5ca9ae1e8659c5f9321c3d6313c49f5068f9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_appliance."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df5ee178915cb667239ec9496166247e"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}