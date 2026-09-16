rule sha224_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a1="4d8f45908245b2a55cc49ddd019c70e37b4c49f2e7e948539b942ffe"
    $a2="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a3="a2f3de94b2cdb6e42bccdbddb2a49b9044d5a99d5c850a2f2d1ec4be"
    $a4="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a5="6eaa7e19d383862d4e6fab499b0ebf952b1ff87fb6db646f53d36d63"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="4676d443ce4e95237fb5ac3e499bcbc18316d1232a9aeec234ce9f92"
    $a9="8c1cc174e604952e5354221d4c6294b63059e873daf690b2cc88a481"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}