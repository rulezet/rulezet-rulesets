rule sha3_384_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0238d91da7ecdc52168d739c610378d8aa9c562e900621351e4e3382f5ca77503f23e6ffd6acba1777cac5897c6fe5e3"
    $a1="ffdac43a0d42b96c9c21cdc7d3305f26ff0d397e29ee6c88cb4f4531ed7c6809cf5ddfdb01b0a334dd0360db73242564"
condition:
    ($a0 and $a1)
}