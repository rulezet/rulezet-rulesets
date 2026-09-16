rule sha224_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7b6d21913933d111b7d38a6f2554e86b76d128acc15a588310f0f15"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a7="81dab7300100a9e496e95d1194690fe14401c3ae8dae4b1f79addf23"
    $a8="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a9="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a10="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a11="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a12="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="4f262d752cac96a9ada895719bb1ffc3c0e916c16fff93db5e716b7c"
    $a15="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a16="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a17="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a18="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a19="b8af66a764892e747457a74abb87bee75c0818f70c364c72e1e51ee2"
    $a20="408610bc629bf7ebae9f88a6fe484b702acfd2acdfb5c172aa3a581f"
    $a21="d61b015e13032015cf9630b6d4d156bd163b33865c5630653976b965"
    $a22="4289543e5f9bb50dfbed9a8ce4fd47d2b9d5a8af87d46b9eae6dad0f"
    $a23="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}