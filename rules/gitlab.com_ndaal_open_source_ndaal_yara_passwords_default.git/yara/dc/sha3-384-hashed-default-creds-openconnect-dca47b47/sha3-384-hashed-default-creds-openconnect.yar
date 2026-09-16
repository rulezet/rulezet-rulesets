rule sha3_384_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a3="ef5543deb4b3d69d67ee03d2bc196338f13e5f8fdee290ff03f8a239ffd92f1fcc73b944e5eb9a8fc2f86efa536e8c57"
    $a4="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a5="0ffb48c488a6cac65e53daf1b23c252dbc5c9d8b9db45090c24cb8e97cbabf903939a8b624ca342a67632b2e94d51f55"
    $a6="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a7="236a146b382d610556b4f079e9c57e216cf5fbe207fc431d0e437a76268c6d10e77f7095ffb46d31b3657f66d34c217e"
    $a8="2d39c734a534bc6bcc705c5b3779fbb96fbb9d6bc872afd394753945fa39e72251d41a333be6cba95ed2d4e15409a3c9"
    $a9="c0f39e696d6fe9654df897fac572d7aaf295705661716b59615d2b0746941a9ccd2226adb99f94690b35b950a23a0c9d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}