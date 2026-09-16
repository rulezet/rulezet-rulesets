rule nthash_hashed_default_creds_garrettcom_magnum_switchweb
{
    meta:
        id = "16xlpcafNrAzlVQW63dSBX"
        fingerprint = "5e01c42be0485b976ba7b46c4cd1afd2a4f00e1cc5c797753aec8d83f16ef514"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for garrettcom_magnum_switchweb."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f938b53b982f22cd6b1c14ae10665480"
    $a1="f938b53b982f22cd6b1c14ae10665480"
condition:
    ($a0 and $a1)
}