rule sha3_384_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
    $a1="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
condition:
    ($a0 and $a1)
}