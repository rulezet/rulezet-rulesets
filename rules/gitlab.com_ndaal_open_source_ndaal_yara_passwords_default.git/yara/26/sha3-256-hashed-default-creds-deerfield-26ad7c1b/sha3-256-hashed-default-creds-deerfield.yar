rule sha3_256_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffddc2231ea407832935a105535bce20dc28ce26fd1c0812e6b47f004b5b0581"
    $a1="00e67d3fef5c31e9318181207e10be6c6b84d52d949f809e231ecb9165cf3e26"
condition:
    ($a0 and $a1)
}