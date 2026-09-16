rule sha3_256_hashed_default_creds_liquidware_labs_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liquidware_labs_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a347294427c8865c0ccc12a737dfe510fc0f8a8ecd1ae68370bf15c2b30dfefe"
    $a1="d2dd47ce498a42c13efdec56421a9f0216f878f3f797c0968be4610962fa5d28"
condition:
    ($a0 and $a1)
}