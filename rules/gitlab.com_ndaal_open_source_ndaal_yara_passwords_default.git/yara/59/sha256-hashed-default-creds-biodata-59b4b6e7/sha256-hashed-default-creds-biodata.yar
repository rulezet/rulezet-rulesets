rule sha256_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c497cdfb9e89265c0af6aadeffcf2c551151513aeeee36a145669b734b2e8d1c"
    $a1="b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910"
condition:
    ($a0 and $a1)
}