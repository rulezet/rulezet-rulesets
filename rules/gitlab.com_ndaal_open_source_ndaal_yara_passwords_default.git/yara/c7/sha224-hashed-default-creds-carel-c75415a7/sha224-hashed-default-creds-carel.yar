rule sha224_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd0e23c742bc3298128817659a431d68421e77d4da85d702563c1608"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="6cc18f4090de553413e94f6152a40d2a2990ad6bf8c09a31fb11f352"
    $a3="2d36617f9530f3ec59f9bf9b0b41d524e5d773aa3efb6f7def1115c0"
    $a4="71df19a0b41572e1da049f58bda18c831e1ddbf2e73954a976456cb0"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a6="27982fca7ed3224baf4d20c8b958a934d4d4def1a97c1bfe7e571563"
    $a7="24f0be6b3f6173d2c7ff7953c52837be32fb6a6b2493ae6400dafb0a"
    $a8="9443b63a009b867ff1ac985550fd67db0573be868e58e5abc184d10c"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="c46ae1c520133e364d5b45bd235e3f1e324b1ce2c8748d217b23edba"
    $a13="9ff2e07b7649a2c0317a6a8d57057b4ff621385b13a045a71a014241"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}