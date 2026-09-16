rule sha3_384_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="713c7fcf2680a4f564d9a03a7f0d7ba60f16c9e9012ffc1bd1e5ed4ef6b6d4bb32e38edafaf0b7d315766b3a971ba18a"
    $a1="713c7fcf2680a4f564d9a03a7f0d7ba60f16c9e9012ffc1bd1e5ed4ef6b6d4bb32e38edafaf0b7d315766b3a971ba18a"
condition:
    ($a0 and $a1)
}