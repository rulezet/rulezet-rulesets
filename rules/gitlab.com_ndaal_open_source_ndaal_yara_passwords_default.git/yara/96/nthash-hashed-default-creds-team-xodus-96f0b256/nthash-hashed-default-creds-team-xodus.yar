rule nthash_hashed_default_creds_team_xodus
{
    meta:
        id = "5WXp9eweOiRbW8IPaVLvrt"
        fingerprint = "2fdf2e7f66f2dc38bf7e561c22d9b025aef715a4de61921c45ba13ed9499b216"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6f127141c658011b76741916b57c41c"
    $a1="e6f127141c658011b76741916b57c41c"
condition:
    ($a0 and $a1)
}