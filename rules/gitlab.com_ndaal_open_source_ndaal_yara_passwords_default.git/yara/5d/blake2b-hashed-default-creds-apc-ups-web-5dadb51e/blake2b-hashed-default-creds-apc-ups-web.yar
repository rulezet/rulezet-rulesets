rule blake2b_hashed_default_creds_apc_ups_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
    $a1="13e565505fef410e20e6131d848116adf3c7a5632a99f9110cf87391c4e7594e50f7d408765e0c9777f7039b8fe673ffa62bf10194799ec96b0cad5eaf777538"
condition:
    ($a0 and $a1)
}