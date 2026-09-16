rule sha3_384_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102ca1d60a29775858edb4da0c35c174bad000b415fa0053adfc9ffeb4fa53bebcee75ce0f5d8bdd2d28d7ed9d1930aa"
    $a1="b36f73c12d63501af37e7a2accc87cae533b760ea581f43d21cc246b8a428bebac8bed747b266b00569df79b6a5413e8"
condition:
    ($a0 and $a1)
}