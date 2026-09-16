rule sha3_384_hashed_default_creds_meridian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3e35699f5b5c65615b9b77e56cf9a027927da2779f7e249a2971408801ee28c739c2de9b95a8bfc94647e1033239a71"
    $a1="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
condition:
    ($a0 and $a1)
}