rule blake2s_hashed_default_creds_iris
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a1="5ecc4f111a368c8de158a367aa9af220e459244f983ccf5ffd6053ebbe160556"
condition:
    ($a0 and $a1)
}