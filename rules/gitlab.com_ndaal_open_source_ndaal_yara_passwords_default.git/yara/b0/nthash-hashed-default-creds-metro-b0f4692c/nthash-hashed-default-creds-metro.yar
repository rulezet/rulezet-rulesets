rule nthash_hashed_default_creds_metro
{
    meta:
        id = "1xcZ9fbwZbAVpHtseYdvDV"
        fingerprint = "ae57b4b7f7fe7fb087d0d4bc45228e4134f2a31ddfd8d6e1924ac2930a46c388"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metro."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09e55a127f3d4e4957c77de30000502a"
    $a1="09e55a127f3d4e4957c77de30000502a"
condition:
    ($a0 and $a1)
}