rule blake2b_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64e86c28ec6dfaf731effa4b87e55eec33a0b2c1d41ffa36809375c3e85ec4403961e5955555e01e5d7455d1d03d2e52bac5e80885fa1200961266a9992f440d"
    $a1="64e86c28ec6dfaf731effa4b87e55eec33a0b2c1d41ffa36809375c3e85ec4403961e5955555e01e5d7455d1d03d2e52bac5e80885fa1200961266a9992f440d"
condition:
    ($a0 and $a1)
}