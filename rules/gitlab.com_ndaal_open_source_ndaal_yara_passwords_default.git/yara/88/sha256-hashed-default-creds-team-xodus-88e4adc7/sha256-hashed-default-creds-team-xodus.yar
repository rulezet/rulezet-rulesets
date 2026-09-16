rule sha256_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f711da60664c04c146d7a47b722c38a8d0bf46c3f52c2084c5c8d1cb78138e73"
    $a1="f711da60664c04c146d7a47b722c38a8d0bf46c3f52c2084c5c8d1cb78138e73"
condition:
    ($a0 and $a1)
}