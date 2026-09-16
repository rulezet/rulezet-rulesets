rule nthash_hashed_default_creds_stulz_gmbh
{
    meta:
        id = "Gqwz75wMpj22eT8JJSBrQ"
        fingerprint = "7647e42faddfa0a694b874f6580ea3c9bc0c90f85af8683d8cda9f347ff32dfa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae162523537262be0e1f5b85ce9d5118"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="df442a853c5c2b57584f2c6b2a59c6f5"
    $a3="d144986c6122b1b1654ba39932465528"
    $a4="b705a5d364ee2397fbc442db1e50ca5f"
    $a5="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}