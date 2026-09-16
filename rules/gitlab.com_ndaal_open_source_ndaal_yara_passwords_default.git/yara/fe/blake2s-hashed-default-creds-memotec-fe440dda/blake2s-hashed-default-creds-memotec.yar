rule blake2s_hashed_default_creds_memotec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c417c6a97cf0da54c21c5214ff25871cd5298dc953f5e8c8c517659eadbf44a4"
    $a1="350ad36ebc32b36e6c25b9177eb3992c76d3d9e9c14b8c859e4a87c69f6873ed"
condition:
    ($a0 and $a1)
}