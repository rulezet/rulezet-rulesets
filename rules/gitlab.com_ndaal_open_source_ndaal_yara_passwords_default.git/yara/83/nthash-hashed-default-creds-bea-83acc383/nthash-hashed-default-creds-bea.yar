rule nthash_hashed_default_creds_bea
{
    meta:
        id = "6aJkQFt4xX4I6W00tz1ojX"
        fingerprint = "62206ff33d2b472e8c5411ef4c785b96878065d28d49a58b223f149ccf8d3674"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="58e8c758a4e67f34ef9c40944eb5535b"
    $a2="d5e9e0db50ba46b948853221be26da2b"
    $a3="f441f41aa59214cccc3d4ba5ed1550cc"
    $a4="50838b21bdef4bbe69c770f8ee7169fb"
    $a5="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}