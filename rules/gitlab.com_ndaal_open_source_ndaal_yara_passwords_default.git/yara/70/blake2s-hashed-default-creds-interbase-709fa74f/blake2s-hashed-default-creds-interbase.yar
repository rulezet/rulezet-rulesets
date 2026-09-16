rule blake2s_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1afd6171483ae4dd7a2baf511850ebc9900b1adc9d8c37823a7a0650461a2c72"
    $a1="2c7e219e70e3709ea4da62059a7626ef9b1d375724dfd9edf713c3ae3107d225"
condition:
    ($a0 and $a1)
}