rule blake2b_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
    $a1="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
condition:
    ($a0 and $a1)
}