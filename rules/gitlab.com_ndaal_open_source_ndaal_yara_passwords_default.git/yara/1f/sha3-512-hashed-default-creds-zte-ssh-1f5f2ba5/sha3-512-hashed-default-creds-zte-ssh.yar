rule sha3_512_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d572ef7d586b9b321c279832fc888ed002b9c857f139b7d933cd4d71f0d50fb37bd9e7b340b7d14558215f1798ed4c0e03a4946f73d0b10f523158b6514f0349"
    $a3="d572ef7d586b9b321c279832fc888ed002b9c857f139b7d933cd4d71f0d50fb37bd9e7b340b7d14558215f1798ed4c0e03a4946f73d0b10f523158b6514f0349"
    $a4="c0cb1bfa7c121f61719b34afd546a586faa76fc45abef34bdc8ee2b219638fe2184cd120136e4bfc918f900a64408d482c7eb30a8c7cced0cf988e75066a9d83"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="024a4739ae3b627ef99c691e7ac72712c900aee2e1940794858380fe03c3328b21f20f2a97418a97a3261ce03c32e3a4e0d59e0a94098d620cc24ab50d88719a"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a9="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a10="982d80e8264f2a7d61bc38d99aa24de22c4121d527d42ecef1ec418725c6cdf3fe8b07d4a2106147cf167a41551fb04dc81da279c9f779aac428ff15a4ecc73c"
    $a11="982d80e8264f2a7d61bc38d99aa24de22c4121d527d42ecef1ec418725c6cdf3fe8b07d4a2106147cf167a41551fb04dc81da279c9f779aac428ff15a4ecc73c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}