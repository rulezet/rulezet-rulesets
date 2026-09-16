rule blake2b_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="f8f7d4cf34169fba37978f77972a1261ec3731be9d53ce8a4afc684a42226a19f3ee17578b0a838d75d8e5b0bb0dc2782eb0ad8c27971af4ddf06778c06d0dd5"
    $a2="910a5dd56e159138447be1627f041efd4a2d76795420b001460c9088f4e0d9d5e7e32276518544b40ac958491793d557b62fe8c1141794bf94ee98ffe681283f"
    $a3="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a4="4da10ad39159033a05182ec267c0b6bd8b5cb5953dc1a26a501a57343ff4412108c3dc266fa51453c720fe3634267d31614f4dc87c954f78e66b996472e466fe"
    $a5="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}