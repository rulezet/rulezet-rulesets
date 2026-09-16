rule nthash_hashed_default_creds_openelec
{
    meta:
        id = "6mgC7yNKLKX0PxgqVYwjBg"
        fingerprint = "78db707ba2b017ea79f0a81e0fa3500b5129fdf82d07440aa4322d5f58d20c51"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd1de9881cd4e0f7bb8427de3c989523"
    $a1="e2b52fdd7824828dc277e4454d26f155"
condition:
    ($a0 and $a1)
}