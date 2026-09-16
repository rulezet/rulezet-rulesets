rule nthash_hashed_default_creds_andover_controls
{
    meta:
        id = "RWaMSUmN6evHYIX5WAJJt"
        fingerprint = "8b7d39c6c81b14bf52b2778f33b15ed36e3525938ad5d69a3b6db71bc5a6f3c0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="387edee24258aff3db65fbe3ca38d669"
    $a1="387edee24258aff3db65fbe3ca38d669"
condition:
    ($a0 and $a1)
}