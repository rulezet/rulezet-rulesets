rule nthash_hashed_default_creds_xampp_web
{
    meta:
        id = "430HFeVdCBjYmmlW3yg2a7"
        fingerprint = "6e34b0c1b032725cd5abf2cf47a04f9206b66264eba943c10eda0ac01acd79ad"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a470dfa4825d16736c4e8d24a32e1982"
    $a1="8a932e577302c7eec164aa380ccec204"
condition:
    ($a0 and $a1)
}