rule blake2b_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17d7776c04f7cec80d710a6100cb73b6b4297236a61d87c62afe091ca9778690d452e3b97695e2b85dd872e24e085ec5202c4ad8d527a8aa0f58632848a255b7"
    $a1="17d7776c04f7cec80d710a6100cb73b6b4297236a61d87c62afe091ca9778690d452e3b97695e2b85dd872e24e085ec5202c4ad8d527a8aa0f58632848a255b7"
condition:
    ($a0 and $a1)
}