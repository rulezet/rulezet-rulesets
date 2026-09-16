rule sha224_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb569643d7baf861d443baddb4da13f38eacb332351c7ebf2621334"
    $a1="ecb569643d7baf861d443baddb4da13f38eacb332351c7ebf2621334"
    $a2="3737994ca1574da975559f9ca959e023d54a05ebde574b213c442222"
    $a3="3737994ca1574da975559f9ca959e023d54a05ebde574b213c442222"
    $a4="9db139931d729312e0a0868e3606df1fa7396685351b5782270e7763"
    $a5="54841f196e3081266db2c2f44cdae8a1ecd29bf46b7df4aa37535bba"
    $a6="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a7="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}