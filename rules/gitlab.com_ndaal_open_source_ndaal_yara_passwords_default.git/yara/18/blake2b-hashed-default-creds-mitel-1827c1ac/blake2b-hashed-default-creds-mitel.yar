rule blake2b_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a2="7ddc031d248afaa667adbbf62b2ac3c51adfe92e03e096ad5bf18744fa42c4d1a0b5b3b77163d297cf6fd6af0f05efca0051babe5f4fa0ec0e7a8fc62a39997b"
    $a3="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a4="3b4b8361cdf7e18781e0219dd1d2fc2afd20c9a4169607aa1f6c7bb993f4e9612edd7ba0db4c837d85a63813a0abc32a3304950d4502960481fff2ae1eb48b4a"
    $a5="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a6="c6c0d57177a4da5c7286ab21cc85f3a9b94855c213d6a74dc49aca11ee54c812288f673086fd33fe1e0a4d6ddd619b7d54c60a01ce2a6b417f4d38b9c5701c44"
    $a7="78029416f2a036f9bbee2b4519a452479916558edd66a43816bcce88d4b0269a8bb63062747ee448b35fdd05b00abeaf5003014087011ff134b7a00487caaccd"
    $a8="a540371e43a8bb9b216fe593f5244244deb9d07c89dc0b2b0ab8f37da9d9d486eda2f2134b0c71d5703f299376868a0980d9774debe94950948e2d7ad731c8ae"
    $a9="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a10="368124278d8ad5057ce1abafac2b9b1f840600db8f7714cdd636017624dec28d3af1dea646c382b638b40c09dc695e9222f864e6b249f7afa5ee51ebdd5e533e"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}