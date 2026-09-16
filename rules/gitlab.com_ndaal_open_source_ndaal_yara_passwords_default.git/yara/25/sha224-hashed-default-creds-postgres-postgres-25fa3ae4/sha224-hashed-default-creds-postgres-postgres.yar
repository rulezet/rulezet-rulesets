rule sha224_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="4fc07c8146ff8d20695edb3d980fab332183eb02af267d5d68de188d"
    $a5="fc821e0b0847b80d23696d188e9c8bc36248099f61657fe7b7921fc9"
    $a6="78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"
    $a7="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a8="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a9="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a10="b32e5865214ba5b064445473cbced17470582e0d48f74f1ba1c4fd0f"
    $a11="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a12="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a13="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a14="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a15="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a16="5583f387b1da968ced7c8da81d954f37516de091ad13993ad1317ed6"
    $a17="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a18="5dfc3a8323baf0e115aa76fe8bd0c8c8b4bb82815d5b91edbc005dbb"
    $a19="5d8da7f8dafede7ed35d07f1500855ea0a71bad43242226140395511"
    $a20="5dfc3a8323baf0e115aa76fe8bd0c8c8b4bb82815d5b91edbc005dbb"
    $a21="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a22="eed7b2cbd1ee238a7d30cabd77310e9a772065944ed82fc99dae2ef4"
    $a23="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}