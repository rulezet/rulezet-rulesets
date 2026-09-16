rule sha512_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df801d823f7c5228a19afd14b6dd4f50283d1c280a8dc43591b5d2e40c1d27c338b91a90c2e5703c45908c065740676385f1c1153d89d4e0365d3dc15b4e2133"
    $a1="df801d823f7c5228a19afd14b6dd4f50283d1c280a8dc43591b5d2e40c1d27c338b91a90c2e5703c45908c065740676385f1c1153d89d4e0365d3dc15b4e2133"
condition:
    ($a0 and $a1)
}