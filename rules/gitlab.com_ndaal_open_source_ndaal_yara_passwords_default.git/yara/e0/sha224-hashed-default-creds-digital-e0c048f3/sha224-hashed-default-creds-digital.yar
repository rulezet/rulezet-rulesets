rule sha224_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b422dcfa018ce6f6d2454b956382a957a129abab22e4f2db2953987d"
    $a1="58b2aaa0bfae7acc021b3260e941117b529b2e69de878fd7d45c61a9"
condition:
    ($a0 and $a1)
}