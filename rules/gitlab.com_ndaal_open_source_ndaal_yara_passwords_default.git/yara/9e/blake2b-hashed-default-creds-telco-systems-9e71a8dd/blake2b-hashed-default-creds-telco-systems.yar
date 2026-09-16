rule blake2b_hashed_default_creds_telco_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telco_systems."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d0053284fed98afcec92bfbad2bda4bf58fcad95899ba2c70f6981d454a2ca847d7f55278fd05be1f6c5fd13228f09873b86607177be6e4fba3075483c1ccac4"
    $a1="d0053284fed98afcec92bfbad2bda4bf58fcad95899ba2c70f6981d454a2ca847d7f55278fd05be1f6c5fd13228f09873b86607177be6e4fba3075483c1ccac4"
condition:
    ($a0 and $a1)
}