rule sha3_256_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eb7b132b35b5b14b7f8c3a692cecf87ee62ab9af5e31c7b11cf333a997a0e05e"
    $a1="eb7b132b35b5b14b7f8c3a692cecf87ee62ab9af5e31c7b11cf333a997a0e05e"
condition:
    ($a0 and $a1)
}