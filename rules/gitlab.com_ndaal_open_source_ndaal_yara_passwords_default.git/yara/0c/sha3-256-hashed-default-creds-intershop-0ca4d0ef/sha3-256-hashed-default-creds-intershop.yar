rule sha3_256_hashed_default_creds_intershop
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intershop."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9bb8f1bbb0c9ed1ce0270359abe6152c9d47afdf2c633407a8c741f4bb598610"
    $a1="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
condition:
    ($a0 and $a1)
}