rule blake2b_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b7dceb516fb3ba35b7db1bcae92a23972790a8f392d1294c496031169c0892ab7ceed62ee3d8e0d2dbf4df84851d1d567544b410fb3fa988c2378e3dd0a5b21"
    $a1="2d130e17ac0a62f5b3f3235834dda84e8c81ea04ebf49025447375c767f033a288c9a56c1b04e4149fa7965200018bace11a42d66f4506cbdb13f9e8c962a2ad"
condition:
    ($a0 and $a1)
}