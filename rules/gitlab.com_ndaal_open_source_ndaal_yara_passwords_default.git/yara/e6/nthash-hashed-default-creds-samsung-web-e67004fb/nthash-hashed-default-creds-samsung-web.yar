rule nthash_hashed_default_creds_samsung_web
{
    meta:
        id = "7i8UehO4jx73zK2HyqqkCG"
        fingerprint = "cbfbe78406ca4bf4c6b18f2734eff46ad9962b8aac6293efbf7c3bc0a452e8fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ade566c9bafd9e5e741889ec6b0e9579"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="05b073daa9c1b3b909ff5ae2e4604bb5"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}