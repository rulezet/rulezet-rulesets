rule sha256_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fda0254c0a5b76a0c86430085fdbf4d8c0b468e521f92b1678e1994b1d708b15"
    $a1="fda0254c0a5b76a0c86430085fdbf4d8c0b468e521f92b1678e1994b1d708b15"
condition:
    ($a0 and $a1)
}