rule blake2s_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e6122b8fc74b91de51c5f3be9a59b4ce575d9fc952d6f8ed5165b486cc6b69b"
    $a1="8b306df5215c0269425964de47d9c006ca0b069438231c2a68e9b4b535d81c0c"
condition:
    ($a0 and $a1)
}