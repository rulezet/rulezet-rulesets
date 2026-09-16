rule nthash_hashed_default_creds_jd_edwards
{
    meta:
        id = "5kynThAvKdrPYjgyUGiGB7"
        fingerprint = "fa6706377b1cc3cdd98c709e9fb765b85ffab74f4c4794224fe0ee9321c1fba5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f3760e941d939214ed694d604dbcd67"
    $a1="2f3760e941d939214ed694d604dbcd67"
condition:
    ($a0 and $a1)
}