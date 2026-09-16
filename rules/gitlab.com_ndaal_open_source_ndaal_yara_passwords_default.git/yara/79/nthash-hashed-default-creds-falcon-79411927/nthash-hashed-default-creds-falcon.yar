rule nthash_hashed_default_creds_falcon
{
    meta:
        id = "50xCfUqx4HGrizHzPaan0V"
        fingerprint = "c2ebfa4b47fbd7b9f8ebb68812988b92ce515206da33c160959423157666e269"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for falcon."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="c6a54973382b771516241add59e80ef0"
condition:
    ($a0 and $a1)
}