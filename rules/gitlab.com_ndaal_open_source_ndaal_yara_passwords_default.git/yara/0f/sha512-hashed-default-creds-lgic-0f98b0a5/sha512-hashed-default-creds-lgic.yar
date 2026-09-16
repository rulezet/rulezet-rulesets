rule sha512_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5a201d6e6a4afbf195ce69e50de17ea6e231c94283972964de52500e8492c622e010fdea2111494ff13b44d957a5b5789556826135b29c88e4c910713fe65bd"
    $a1="b5a201d6e6a4afbf195ce69e50de17ea6e231c94283972964de52500e8492c622e010fdea2111494ff13b44d957a5b5789556826135b29c88e4c910713fe65bd"
condition:
    ($a0 and $a1)
}