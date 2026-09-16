rule nthash_hashed_default_creds_frontrange_solutions
{
    meta:
        id = "58uaBrhCYh8dqQpXJuQFo8"
        fingerprint = "5614b315e7f1db4a52cb39a6d2120210c230556e6bd96570ba2a018ee63fed2a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for frontrange_solutions."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e6342ecc5ed563057800830d710dd61"
    $a1="6d3986e540a63647454a50e26477ef94"
condition:
    ($a0 and $a1)
}