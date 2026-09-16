rule sha224_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a2="7052a6177e32a37a2afe962ae2cbdeb9f66b732dd2728ff4b72b6c70"
    $a3="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a4="b5b30208ae87c74576c6d25caf56b4056c4c231a12e4e7efd3f23d9b"
    $a5="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a6="f372f6497e53dbadc744424593881d57e2536173ceac4a7542b1d476"
    $a7="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a8="9de5a8a043c194ded5357311049061a33092ea93db18013be8ce06f1"
    $a9="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a10="2cfcbdc839cf550004a0115a366cd5260becb7269f038e2a1911f44d"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}