rule sha224_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65335da024e1e7b60ec0e63c69807e0043d5562a942e9da5ddbf3dba"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="b08eae280a1059344bad6e8c498cfbc928abf4fb005a3d704f63ec39"
    $a3="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a4="45ebe56040d36c09aa907a6946213289dec195d146e2033092607056"
    $a5="79f95ce631a460dc2e3d220a5dffbb5616074375648e4a2212127ecf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}