rule sha3_256_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a871cd4e7a17d4d7e77ae38f8b7d82c0b4857cf0b6e3647bc9f498f4fb191571"
    $a1="abafb3efd43be953e6651a13dc797d09e799e68fc6172983374d38ca47b4e4d8"
condition:
    ($a0 and $a1)
}