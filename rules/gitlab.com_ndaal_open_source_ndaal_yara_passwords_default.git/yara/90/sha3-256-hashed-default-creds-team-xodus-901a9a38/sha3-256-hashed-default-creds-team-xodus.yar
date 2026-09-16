rule sha3_256_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a243aaf3c9d0b7ca3da869e7366affaafd2d38d7c8f74ce3ab8886c0d970adc4"
    $a1="a243aaf3c9d0b7ca3da869e7366affaafd2d38d7c8f74ce3ab8886c0d970adc4"
condition:
    ($a0 and $a1)
}