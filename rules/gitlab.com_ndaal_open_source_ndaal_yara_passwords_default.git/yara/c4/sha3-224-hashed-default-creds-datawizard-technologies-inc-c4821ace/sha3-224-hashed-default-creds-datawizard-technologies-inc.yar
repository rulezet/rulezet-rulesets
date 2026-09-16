rule sha3_224_hashed_default_creds_datawizard_technologies_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizard_technologies_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
    $a1="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
condition:
    ($a0 and $a1)
}