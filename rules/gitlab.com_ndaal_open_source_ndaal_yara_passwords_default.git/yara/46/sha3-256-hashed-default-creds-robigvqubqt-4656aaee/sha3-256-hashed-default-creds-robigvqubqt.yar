rule sha3_256_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2340fc30f8e2806e84e6bd6ea5672791ed54969a58e3173922a13af16e922d45"
    $a1="e7093154cb7f2ca1c1f949120010b2b5d8ee79fd1f60bcc4f4753d1ffc4e8e8f"
condition:
    ($a0 and $a1)
}