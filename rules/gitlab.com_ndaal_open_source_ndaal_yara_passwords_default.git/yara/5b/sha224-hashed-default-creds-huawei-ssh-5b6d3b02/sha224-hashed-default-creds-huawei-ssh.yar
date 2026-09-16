rule sha224_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a4="838fc8b0cb7ebe2832d05dc3e7b373572b6f5381d19073650b5f30fc"
    $a5="838fc8b0cb7ebe2832d05dc3e7b373572b6f5381d19073650b5f30fc"
    $a6="535f266f3254bd5c3dc1c5d0a8ea5e5a3c113a6048f473fc86d6a178"
    $a7="7493a7051f66564aa3d1345443b4b5dc1e6c4ba5545171949025b714"
    $a8="007ec7afc4f088819773b83c16ca3cce7bc680a8019b9545223e0aa5"
    $a9="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a10="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a11="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a12="cdef3e7447abf28dcac458f6118fd8f5d9266e871e8c9861a7b45ec6"
    $a13="cdef3e7447abf28dcac458f6118fd8f5d9266e871e8c9861a7b45ec6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}