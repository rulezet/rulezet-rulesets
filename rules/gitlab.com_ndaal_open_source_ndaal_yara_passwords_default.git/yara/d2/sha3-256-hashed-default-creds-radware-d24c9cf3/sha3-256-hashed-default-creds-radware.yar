rule sha3_256_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
    $a1="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
    $a2="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
    $a3="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}