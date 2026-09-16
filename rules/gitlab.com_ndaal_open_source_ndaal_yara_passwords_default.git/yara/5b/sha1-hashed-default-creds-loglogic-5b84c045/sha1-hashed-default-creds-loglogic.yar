rule sha1_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="545497203ac9b57e2d69d9e81577ee54558b9f48"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="545497203ac9b57e2d69d9e81577ee54558b9f48"
    $a3="435b41068e8665513a20070c033b08b9c66e4332"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}