rule nthash_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        id = "17EsSnxWghXXH1oePT6rwu"
        fingerprint = "4a5e598025d625abf41c404e3942979c47988e6ab7679fc4e673662e10a0947e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d2b4dfac512b7ef6188248b8e113cb9"
    $a1="3d2b4dfac512b7ef6188248b8e113cb9"
condition:
    ($a0 and $a1)
}