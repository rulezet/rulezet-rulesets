rule sha3_384_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13f6fa73062634737a3cd2602dc784beea9ba31c0b7f72a0f8ccb4c5adfd211cd983c5b7542a1c715fecaff0e8291c5b"
    $a1="e662e82f18d6d31ad1835f48cc98f4245688735c8ebf3930af6faa186550d24a2845865836e8d9a5260fb8a47be6f4dc"
condition:
    ($a0 and $a1)
}