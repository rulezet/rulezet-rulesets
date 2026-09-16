rule sha224_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30c511656eb9ab11a255c09adfcdba7b155f2b5988a0f495920454e3"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="bb3dde385e8be09d6a46a981d471fe621ee35f79d5423e2faeaa9e3f"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="4fc07c8146ff8d20695edb3d980fab332183eb02af267d5d68de188d"
    $a5="db0bafbd3f64a116889d8d32eb9116d8c91a805ac22a66d2f21ae07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}