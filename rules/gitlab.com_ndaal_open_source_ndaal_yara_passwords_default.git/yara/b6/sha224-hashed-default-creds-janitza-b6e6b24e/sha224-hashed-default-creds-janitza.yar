rule sha224_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
    $a3="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a4="95e95c8a6c039e07ae1711a99c0cfc86e132c573fec7ba4869bf570b"
    $a5="2857183a6807620c353a06f18c7652c4f8e63c7aac29ba79e84d2e55"
    $a6="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
    $a7="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}