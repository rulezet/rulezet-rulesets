rule sha3_512_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6934ad0a7fb61967d1e74352c50466f935ef8deeecd695f236a11602a118dcc7adf559af0af77525c08eee7d455a30e72f4b813d2e51bdee70735a4d2c5805ed"
    $a1="5e3990769f7e721b37ff5101c129ea64c34552b9a22ce9b63d933b22ce8d65a9a5725341e0f8bb0067b9815323237c4f7899b0e3533c1d5f79addd08130a46b7"
condition:
    ($a0 and $a1)
}