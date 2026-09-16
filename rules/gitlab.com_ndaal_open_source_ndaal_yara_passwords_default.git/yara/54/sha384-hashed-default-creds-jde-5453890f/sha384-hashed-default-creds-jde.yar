rule sha384_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="df72a7cad7d53b30f02313ba73b4326f6bd27ca7a812d82d961d42d5be9fd0403f61fdf82aa9cd2f190a66cc800a05f9"
    $a1="df72a7cad7d53b30f02313ba73b4326f6bd27ca7a812d82d961d42d5be9fd0403f61fdf82aa9cd2f190a66cc800a05f9"
condition:
    ($a0 and $a1)
}