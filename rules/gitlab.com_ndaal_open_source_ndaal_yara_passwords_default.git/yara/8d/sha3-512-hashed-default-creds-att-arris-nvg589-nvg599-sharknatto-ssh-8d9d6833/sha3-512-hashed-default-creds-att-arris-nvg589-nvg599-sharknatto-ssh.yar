rule sha3_512_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b0ee97ed4963927b61130bae71a3d1bba78515ff6484f6279360d815ac273d5da0d7e950206a9e987f62c57222482cedf6565a3358b2a344b155740ec9e03f8"
    $a1="3779292983f4f3b6f2f131137aa2c9be65e3efefd948821f1245c8a4f5307ed763aed021efee775b4820278d15450c974643ecd1131ce09afcc41d99a69a8ecb"
condition:
    ($a0 and $a1)
}