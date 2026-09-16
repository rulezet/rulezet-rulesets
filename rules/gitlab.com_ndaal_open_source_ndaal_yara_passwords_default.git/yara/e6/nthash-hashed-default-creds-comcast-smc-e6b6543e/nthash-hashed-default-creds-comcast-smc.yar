rule nthash_hashed_default_creds_comcast_smc
{
    meta:
        id = "AqwqlYQB3VraYPOXzbtUk"
        fingerprint = "122175b68237befe97d491a7b6c53d241ae5e276c196c8fc2bfe561963760b3e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca7c482af7bcbd6e660a7e307e9a8f23"
    $a1="6c5ec0cf3aa0cfb9b96139eac847b13f"
    $a2="1365f3c68d81a3a228b27e4e4031c84b"
    $a3="6c5ec0cf3aa0cfb9b96139eac847b13f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}