rule sha3_224_hashed_default_creds_luxon_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for luxon_communications."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ab6c44c0557a17ef92cf2af450e43bb87a9275ea19ec9879176b635"
    $a1="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
condition:
    ($a0 and $a1)
}