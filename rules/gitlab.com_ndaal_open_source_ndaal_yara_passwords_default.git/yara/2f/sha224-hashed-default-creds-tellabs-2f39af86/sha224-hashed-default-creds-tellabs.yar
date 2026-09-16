rule sha224_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="596787a6e6f508a97179985eb9083ca2eb2e2c517cbbf02ac1b356aa"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="ad6dad1e4ed2144e4f47689e3e8e24b6b3c8daabf7fbded0aad67da2"
    $a3="e4f5be939b82f85e3389ab75249d927663839b0b9b918621d0e4e353"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}