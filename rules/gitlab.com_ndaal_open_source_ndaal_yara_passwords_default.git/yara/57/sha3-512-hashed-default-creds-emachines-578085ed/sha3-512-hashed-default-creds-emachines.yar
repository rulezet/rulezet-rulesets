rule sha3_512_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b9202aab55055d296965b3c0a8a590bf58f8727d5f810ec3f3322b440d5f7c03517151ab5cf9a9bdffbaeaf01a74376e6b7b8306ddab36311238928abb8a35d2"
    $a1="c8fc64cdc6ad7e2223b7410f869a0fb0715b43bdeb4ed6f6d85d4971064ebabdbd54edbed500b07eb3fb2f4b6948398311bd963761d531085b35ad508e4083ea"
condition:
    ($a0 and $a1)
}