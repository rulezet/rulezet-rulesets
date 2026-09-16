rule sha3_256_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="167756ce76155ba4faace485d41b8b75a8f066bd52394ef7bb27d90242539070"
    $a1="27562d35e43d38adc4e02313fa9982843efeed6e164843d44b1eeddb9ace7326"
    $a2="167756ce76155ba4faace485d41b8b75a8f066bd52394ef7bb27d90242539070"
    $a3="f75b9a62c123b47c2475bce3e47b1ade855fdf8238f016556e672bf8761c449c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}