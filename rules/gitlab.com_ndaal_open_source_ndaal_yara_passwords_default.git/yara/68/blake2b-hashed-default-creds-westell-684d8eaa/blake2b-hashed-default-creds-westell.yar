rule blake2b_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="92716e2df3016f0e45a8b2944207f12b7b4c3c735746120685aa35d3199b555892d14b9effdc42d6f8b6b8ac7965eb94c5fd077384c17771b7559e6260d64021"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="52f7e8a8453ffdc90c4c1de4933b9163aabd2781d7fe323c2c97ea37092862505f016634dcb6004c8d76c88023dc772826d7b03733cb92c12a9e70b557d7f63b"
    $a3="b3c24ab1f361b33822386a881fe2fd1b3e4a829b75e646174365bc2639168cdd2ed5f6ce721613d78e9b8fbdeea6ef592afb3972de5efde61d61dd447727799d"
    $a4="413c45a59d816ff9a30389eba12fc6094322c0a2eb823fa8ff1d0f1040b49060f69a206b952d1628c1eec5783d0e6dbb7038057c30401c31e6dead93d904d953"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}