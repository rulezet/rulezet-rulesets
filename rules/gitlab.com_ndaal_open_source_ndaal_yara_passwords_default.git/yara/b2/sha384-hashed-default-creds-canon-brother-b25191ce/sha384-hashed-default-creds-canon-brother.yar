rule sha384_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84ed03820e3111ad984790c0e4e9eb953cd3a3d078534f049f30a42122458edcb7946ac05a7170bd202261815b6d5600"
    $a1="84ed03820e3111ad984790c0e4e9eb953cd3a3d078534f049f30a42122458edcb7946ac05a7170bd202261815b6d5600"
condition:
    ($a0 and $a1)
}