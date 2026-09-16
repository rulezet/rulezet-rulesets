rule blake2b_hashed_default_creds_xampp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69a1b472931fb74a59e12d09749c215a2ae8435c0d058c01f457e9396b9f11caeb99e9fba6fdceccef69e513cd403c65c4aeaeb60730043fd3767679b95f2529"
    $a1="597ae74fb139d976f0e28dfda3b6ed18b8a764b8a889d6ba849314677f73ea0b8a732c47730ee1cc7b8eb4fcebb68bc2133fb9ad9e77d5aab3cb2f9782c40eef"
condition:
    ($a0 and $a1)
}