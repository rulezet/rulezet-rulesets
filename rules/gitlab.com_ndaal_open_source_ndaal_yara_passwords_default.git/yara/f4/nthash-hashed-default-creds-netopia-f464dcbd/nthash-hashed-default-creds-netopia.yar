rule nthash_hashed_default_creds_netopia
{
    meta:
        id = "7NTO4CtJRgYKle0gP20Dmr"
        fingerprint = "0c2c9e0c74419b5cbf41de45d7b57aaaeda118f3cb172779ff11b6d4a80a00b6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d07decfcd8194b2be29258f0f971410"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f2a26a379b161ce3df71157f7de6c879"
    $a3="f2a26a379b161ce3df71157f7de6c879"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}