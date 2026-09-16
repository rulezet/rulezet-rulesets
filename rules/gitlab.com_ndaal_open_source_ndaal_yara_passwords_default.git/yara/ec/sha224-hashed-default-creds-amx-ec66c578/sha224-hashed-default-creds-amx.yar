rule sha224_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="565b28acbc67449d22921a34c23d26ad5a0fddcd86d999d0686f83ff"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a4="280c4134e6100040ca1456f1d5ba0a833db60029aca3971ae15cefe9"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a7="8180227f15373c9ed1a11e1fd9a884587e07d7038f8b9eab9c135f04"
    $a8="565b28acbc67449d22921a34c23d26ad5a0fddcd86d999d0686f83ff"
    $a9="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a10="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a11="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a12="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a13="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a14="c2333afcaab4396298702ee9448f334f110a1e4b5bac225854097aa4"
    $a15="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}