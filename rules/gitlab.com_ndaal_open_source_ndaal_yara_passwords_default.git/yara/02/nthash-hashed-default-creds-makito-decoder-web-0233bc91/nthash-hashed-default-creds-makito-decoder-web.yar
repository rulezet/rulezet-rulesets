rule nthash_hashed_default_creds_makito_decoder_web
{
    meta:
        id = "WRz4Yvzmz5v19NQiWeccZ"
        fingerprint = "b77a9e9b0b32b852426e42ce12caacfac73b931ac7743e90289b31b4154d0882"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for makito_decoder_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f31ff2f368a0ea307d584425bd12ea4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}