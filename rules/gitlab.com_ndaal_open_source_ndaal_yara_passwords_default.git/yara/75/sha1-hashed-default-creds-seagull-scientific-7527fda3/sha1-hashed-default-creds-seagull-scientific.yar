rule sha1_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="b521caa6e1db82e5a01c924a419870cb72b81635"
    $a2="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
    $a3="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}