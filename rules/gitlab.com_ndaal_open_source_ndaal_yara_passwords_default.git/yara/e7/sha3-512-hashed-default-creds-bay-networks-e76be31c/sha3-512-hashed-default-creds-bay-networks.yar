rule sha3_512_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
    $a1="9590db8c6413f2ef63a7c9c616a73be75b4c1a95fa38a802858077a9e2d4ad8b644be584e0457ed6248426dedecc970259ca575adaf1f0a171c9e0085617387f"
condition:
    ($a0 and $a1)
}