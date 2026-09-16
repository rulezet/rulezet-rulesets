rule sha3_224_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="300d01f3a910045fefa16d6a149f38167b2503dbc37c1b24fd6f751e"
    $a1="11e6fcf8ddb92bc463a509fb133451fddda04d9df7510a3ebd778d05"
    $a2="300d01f3a910045fefa16d6a149f38167b2503dbc37c1b24fd6f751e"
    $a3="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}