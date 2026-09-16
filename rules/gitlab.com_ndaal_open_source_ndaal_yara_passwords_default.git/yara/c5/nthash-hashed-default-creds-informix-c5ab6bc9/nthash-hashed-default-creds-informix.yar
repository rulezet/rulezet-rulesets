rule nthash_hashed_default_creds_informix
{
    meta:
        id = "1HnBGVkEV7WqRK3UXn8K7W"
        fingerprint = "b46d8fbf7000356c0951c3d6ee2497e6499cf08bc6d21e0751526022fa7f2099"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aded0543608ee82c821a55fc82dd1d9a"
    $a1="aded0543608ee82c821a55fc82dd1d9a"
condition:
    ($a0 and $a1)
}