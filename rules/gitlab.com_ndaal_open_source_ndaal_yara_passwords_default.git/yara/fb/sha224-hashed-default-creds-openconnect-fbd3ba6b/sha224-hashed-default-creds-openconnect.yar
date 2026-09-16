rule sha224_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a3="6fbb735206b638f03a9f5c1a5b4c9ff9afdf4e76450b024b316290e2"
    $a4="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a5="ef5210eca043e9e7e9c9c739d467f87351b7c62a502d8fe97f8d9f41"
    $a6="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a7="e377f76fc20600fdc9bf2f5b5d0a93b35ad292462a043f4b4ec691b6"
    $a8="894f442e8ec6ce833d956b04e4ab3ffd521cf15356077e7fdf7ee8b9"
    $a9="49d4e84d5e9b335410f4510afd91b8f9e824ed4d6bd9de1f0887fc07"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}