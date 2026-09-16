rule sha224_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2ffac084974a94d2393c4f48a9e9e0c7b84ec4fc8857f9bcdff45e2"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="9ac4c81d4f926ecc59f4f3eb3e9f4b590fc9828e74654d0e93b2295a"
    $a3="9ac4c81d4f926ecc59f4f3eb3e9f4b590fc9828e74654d0e93b2295a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}