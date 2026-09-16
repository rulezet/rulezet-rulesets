rule nthash_hashed_default_creds_cisco_systems_general
{
    meta:
        id = "3VXFWsRpJKk52xxwHMPIAr"
        fingerprint = "799e9ce3b165bcef447378574745531cc1c103cedff87a7fe53277248ebc14c7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c800f13a3ce86ed2540dd4e7331e9a2"
    $a1="5c800f13a3ce86ed2540dd4e7331e9a2"
condition:
    ($a0 and $a1)
}