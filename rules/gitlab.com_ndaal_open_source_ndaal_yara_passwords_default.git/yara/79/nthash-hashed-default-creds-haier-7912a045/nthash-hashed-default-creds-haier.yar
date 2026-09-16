rule nthash_hashed_default_creds_haier
{
    meta:
        id = "2eZ4ghxZOKxbEOt0bht0TS"
        fingerprint = "eb245e8208a99ee4fb6ee22ea5a257e60d407d131cdcb8e4373be03e2f0cfa7e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="932c88d8463ae986014d4ab6e878befa"
    $a1="3168ada32b86ed226da91faf8667cb24"
condition:
    ($a0 and $a1)
}