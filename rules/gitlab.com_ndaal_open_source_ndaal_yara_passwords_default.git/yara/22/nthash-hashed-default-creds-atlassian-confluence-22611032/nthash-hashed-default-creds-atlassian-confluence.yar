rule nthash_hashed_default_creds_atlassian_confluence
{
    meta:
        id = "1DOY01VzRCkWpROp9OfeUn"
        fingerprint = "a2d0816736c170a903f314e8a7cd153f84267cc09431fbbd17a9418a889b06f0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8b78dce5719ef2bd0c0873185e215f0"
    $a1="99f67c4456885d32a2418fdbc9e0df04"
condition:
    ($a0 and $a1)
}