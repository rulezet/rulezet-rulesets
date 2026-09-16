rule sha224_hashed_default_creds_digicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="4105cace91bc98ece25fabcb60c9fc3ea2ada284b1e49d63b3113a64"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}