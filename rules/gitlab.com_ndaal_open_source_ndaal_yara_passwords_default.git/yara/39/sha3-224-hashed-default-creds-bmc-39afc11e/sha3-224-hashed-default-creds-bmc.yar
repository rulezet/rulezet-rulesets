rule sha3_224_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03bd1d59c7162683d3afade8f5ac9179cd8e1e262170add8bd500509"
    $a1="03bd1d59c7162683d3afade8f5ac9179cd8e1e262170add8bd500509"
condition:
    ($a0 and $a1)
}