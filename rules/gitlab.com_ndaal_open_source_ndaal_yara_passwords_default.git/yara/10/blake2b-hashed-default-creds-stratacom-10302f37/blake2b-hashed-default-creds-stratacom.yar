rule blake2b_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a73e624e5f1539e285c5913f236c6abe07863948cede2a29ffcbaece100206952f439bf5021c2ad3f2c1b0a360acf93046f04697c2943a920906549ffd5f169"
    $a1="45c70ac54f2bc07ee2f2ef6d5bfa419b73bf9d5d3ba10f5b046bb8802ecde33e4df42faab1ee3454213a6d2496a9a9eddabeabfe024b99a54730b853f8720e88"
condition:
    ($a0 and $a1)
}