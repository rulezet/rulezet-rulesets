rule sha224_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e7df61d7b8219986dde0dd3ae7d2ef2a7f0c3d529c3312231ddd2e3"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a3="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}