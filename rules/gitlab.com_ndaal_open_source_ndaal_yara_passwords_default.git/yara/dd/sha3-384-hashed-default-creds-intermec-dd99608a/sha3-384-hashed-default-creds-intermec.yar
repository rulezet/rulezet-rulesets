rule sha3_384_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
    $a1="d9d34b9b1ae143524caa90db6ba0eaae78edaa36a6b6fa7af4a18ad505d075b5b688f140f5d163a08c561a36cdeea4c4"
condition:
    ($a0 and $a1)
}