rule sha224_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="b09ae657f9bb26f9e761879efebdb8dd5b3e72f8061271219b52cf72"
    $a5="b09ae657f9bb26f9e761879efebdb8dd5b3e72f8061271219b52cf72"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a9="2cdc069c1b6c826781363e8277957d71cf5e8250032d2d80babc7476"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}