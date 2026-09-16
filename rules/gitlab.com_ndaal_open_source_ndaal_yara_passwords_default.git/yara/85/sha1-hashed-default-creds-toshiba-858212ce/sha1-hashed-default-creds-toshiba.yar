rule sha1_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a1="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a2="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="cde189cbec083aaad31d890be94b8a68d463fd7a"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="16ff504b76e7521ce35600a80e14680a611b97b5"
    $a7="8451ba8a14d79753d34cb33b51ba46b4b025eb81"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}