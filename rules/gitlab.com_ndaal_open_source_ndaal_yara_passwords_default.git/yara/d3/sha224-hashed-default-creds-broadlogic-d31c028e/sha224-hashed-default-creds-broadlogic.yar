rule sha224_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
    $a1="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a5="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}