rule blake2b_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c5a1796a4955552f5c7efa62253814339cd06c1fb48bfaf55450a2024514fd974e7b2899b7ff971ecef0557aeb2ccb3421214ffd40aecea0caca4fb9fda1bee1"
    $a1="824e069b4a2ac4f916680961c9b3630f402bb64e07a17a999dd560d0c026288282504c5d952bc98c87cd19d59ac9b65a2e3865676bc434cf5925be68c6da0134"
condition:
    ($a0 and $a1)
}