rule sha1_hashed_default_creds_deif
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deif."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="296f6517ffb3c6f69315e07c185ce479fd0b3c8d"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="7505d64a54e061b7acd54ccd58b49dc43500b635"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}