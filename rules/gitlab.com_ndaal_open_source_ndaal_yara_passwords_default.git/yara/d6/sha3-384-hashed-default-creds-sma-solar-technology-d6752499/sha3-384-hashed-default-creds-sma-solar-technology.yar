rule sha3_384_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05a326f665edf95226e953799a22d6595d988cd6132636246a96cec322ff0fa2e82f83768133a879f564c46fcf5e7d4f"
    $a1="3391ccf39b85eda64ce6da54bb4f2afe815585764e5808de578e66d9ae3e7acfde14756d0898f734434adf3357bc469b"
condition:
    ($a0 and $a1)
}