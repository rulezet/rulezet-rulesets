rule sha224_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6938dc9409850a18399fff08d3c01fa25aec807541d25b3b826b16c9"
    $a1="6938dc9409850a18399fff08d3c01fa25aec807541d25b3b826b16c9"
condition:
    ($a0 and $a1)
}