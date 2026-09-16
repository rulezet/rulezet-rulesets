rule blake2s_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07fdd99d5e44b5cbbd0a665c2fe9098d4adea4c9e01a20979518eef220f0086c"
    $a1="07fdd99d5e44b5cbbd0a665c2fe9098d4adea4c9e01a20979518eef220f0086c"
condition:
    ($a0 and $a1)
}