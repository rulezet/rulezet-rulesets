rule blake2b_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32acaf528294e9f37fcb1f1e147a5951e76ade3ee935d9924c228e29a21231b8e30f369a575512f38182d18760509431558a59f9a423f381714997d1b134346f"
    $a1="9e67456dda5d07395c38c8c8f789d830ab93690b1252c7a9cafbf4ae78853bd759b6f9e6da7a1a9fb8f57b3d49f1c4ffc749863a3871e8112643ef8b62eb095c"
condition:
    ($a0 and $a1)
}