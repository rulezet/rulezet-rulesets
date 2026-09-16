rule sha3_256_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
    $a1="2848f07d55acfdd67caf77f276e1f0a529e4026f1708356d77b1ced98326836e"
condition:
    ($a0 and $a1)
}