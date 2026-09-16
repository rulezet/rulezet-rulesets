rule nthash_hashed_default_creds_protocraft
{
    meta:
        id = "2XnCi5bxn3taQLJ3sQPWo1"
        fingerprint = "68ee73d9778dad2e0107f2c4cf8b86e58a4dc9337ac3651155109d5a8a1c885e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for protocraft."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7f5091317c9da29ce62e1d1ba54a4a3"
    $a1="d07fa4a6c97383641ae3880fa7de9656"
condition:
    ($a0 and $a1)
}