rule nthash_hashed_default_creds_tasman
{
    meta:
        id = "27oZkhI3yYlEzn9lEvvcyy"
        fingerprint = "320b50af5b4b01398f3e8580c72a2ab4375ab3085654a3d700effceb7b5a3c84"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d05ad44b808d6e6510204f674157d17"
    $a1="a0073f900e71f0e66dc95c78a49e46dd"
condition:
    ($a0 and $a1)
}