rule sha224_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a1="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a2="bb8dd744c35071084cfc017afee9f3a492b762b93a083a6a5cdcdfe7"
    $a3="41491e96da93d03981b6677040d1ac8f94b68d593fadfed5595e0cb7"
    $a4="b0230b784117e470472294d167c34856eaf68d68b7e9307836464c2b"
    $a5="25193ce5c73a17baa8420eed3f8f139f34447ab0e8da490aaeb10d63"
    $a6="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a7="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a8="f13509df7748da4564145a66d4f7e30313a4cf0be791d98c344301e8"
    $a9="281f836d7681ad99c1cefd501e0ffd132fde05476adbd584e1c1baf6"
    $a10="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}