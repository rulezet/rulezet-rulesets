rule nthash_hashed_default_creds_ewon
{
    meta:
        id = "7H51RvzAebJZ7tGsbuGMRk"
        fingerprint = "a8e6a9ce7521ad4017dd5df7b9467918b047ff3bc53f4cd9261bbbb312b3b239"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e8c03ccbc34f2e2e6cfc57102c91c09"
    $a1="5e8c03ccbc34f2e2e6cfc57102c91c09"
condition:
    ($a0 and $a1)
}