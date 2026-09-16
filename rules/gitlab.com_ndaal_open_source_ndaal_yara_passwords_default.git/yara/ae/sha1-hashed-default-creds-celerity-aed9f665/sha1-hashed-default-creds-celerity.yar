rule sha1_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13ddd0f322b6928fdce2a89911a57fde5dcb84a9"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="46650489a3f38853292962e48708778c135049b8"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a5="09e8ee583731c8064600fa2d5fdc251ed3888f90"
    $a6="15dc450365539fa619d1b4fb5ab2616086c5078a"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}