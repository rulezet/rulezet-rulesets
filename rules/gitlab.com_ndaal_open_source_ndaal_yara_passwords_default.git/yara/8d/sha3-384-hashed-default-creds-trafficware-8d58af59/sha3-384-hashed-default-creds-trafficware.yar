rule sha3_384_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc0d2758f237e31a33ad470e0955291b32811288dd6b3d7331d476920fb8ae38a1fb59f7ad07b0bc598f1acef93f4c48"
    $a1="bc0d2758f237e31a33ad470e0955291b32811288dd6b3d7331d476920fb8ae38a1fb59f7ad07b0bc598f1acef93f4c48"
condition:
    ($a0 and $a1)
}