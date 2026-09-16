rule sha224_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7902f17d6164ee01ca4f8ca79c3e39618b64e93160311f2e8e9d402c"
    $a1="b6ebf0805e8f23a423ccdb6824195fff219f53040e41870933a03b57"
    $a2="e7c6add1676a3f5508b4f9833c5a6deb83848b18d0f82b425365ab1c"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="fb22dbd3dcf0b2ad8e74079e7db330b08b16a9cdca3a446bcc402a7c"
    $a7="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a8="98e6eae7336c91abb2949ddfb5f1c0499cd36d9c3c7b83997703ec53"
    $a9="60a3e7db49689e427d323d69d8a9ef86af02a3b4668bbd9d17e22e50"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}