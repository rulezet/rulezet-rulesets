rule sha3_384_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a1="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
condition:
    ($a0 and $a1)
}