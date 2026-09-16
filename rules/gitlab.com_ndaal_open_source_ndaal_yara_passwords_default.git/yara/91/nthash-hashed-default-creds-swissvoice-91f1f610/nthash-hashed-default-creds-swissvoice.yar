rule nthash_hashed_default_creds_swissvoice
{
    meta:
        id = "1Nrcz96lTFjzlrIshSA7Ik"
        fingerprint = "bc6e18b249c312a115a0c17a8eb42e737c8e1b1a165eb937691a97ae4a8d1aa7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for swissvoice."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="eeac4730110ac22073567d9c08a7958a"
condition:
    ($a0 and $a1)
}