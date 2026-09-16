rule sha3_224_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcd9a1d151c3cfc3a412e2cdd20185e5d6a8803fe0321cc764968d8b"
    $a1="394251e18514267b77adcafab473cc4bac76893cc07a14f4d578a770"
condition:
    ($a0 and $a1)
}