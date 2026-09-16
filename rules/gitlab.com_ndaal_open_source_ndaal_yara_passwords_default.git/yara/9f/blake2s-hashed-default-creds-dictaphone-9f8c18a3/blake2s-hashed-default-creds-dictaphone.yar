rule blake2s_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a1="bcd4b1c877da47b20b5fe711e0e5a47532bd57aca7fbe4e4782a2216df6a0f30"
    $a2="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
    $a3="6e901b6b30bea1f0c3e2afd93f5c720f15c7145b1e6ec0f89ddedb3b8d4767c0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}