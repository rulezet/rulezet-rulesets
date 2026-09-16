rule blake2b_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
    $a1="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
condition:
    ($a0 and $a1)
}