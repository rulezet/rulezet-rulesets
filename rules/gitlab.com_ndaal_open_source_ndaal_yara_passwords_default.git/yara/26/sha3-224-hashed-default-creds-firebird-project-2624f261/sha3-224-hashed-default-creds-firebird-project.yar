rule sha3_224_hashed_default_creds_firebird_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird_project."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65a8b6efd24734f6e40cbfddad07491caab5ef3ec7f783df05aa1f7c"
    $a1="3eb683ffe6602c2cc920568281c655d9ea6f2b790d2633cf643f90f4"
condition:
    ($a0 and $a1)
}