rule sha3_224_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd41a153dd3bed4ec9d8b93a70222a2bec446e6ccdfafa61b6ad7c85"
    $a1="3cb596c5ba498da9930fa77aa3b865f09af4498073f18cad99719f0a"
condition:
    ($a0 and $a1)
}