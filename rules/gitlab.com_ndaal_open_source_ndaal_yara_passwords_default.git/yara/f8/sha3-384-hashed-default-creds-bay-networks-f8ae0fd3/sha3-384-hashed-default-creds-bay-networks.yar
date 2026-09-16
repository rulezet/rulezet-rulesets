rule sha3_384_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
    $a1="e93d6fd44e5a6e57fc6083328ed79695f48fec43cab2e5b2d797084fba8ab17ddcceba629dbbf75c6fef680193fb4c40"
condition:
    ($a0 and $a1)
}