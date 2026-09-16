rule blake2s_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbadfc8cd125762e84e59e61bf19a60c7098d3beb22e6659e5779f1d7d8d4894"
    $a1="d9c31246e6fe87b1fb88a900da2ba135d2a22296810bdd8f6c9124c73e947d59"
    $a2="c94b5aa43d360c0035db4889aad8b9719ba7404d84358ac171aad6f5cfbe3902"
    $a3="831b8a29999f74a7408ad4952ba8d3d0ef82b0c9970869d53422b1ce8b782295"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}