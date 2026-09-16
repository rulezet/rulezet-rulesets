rule sha384_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64eec76b124335a27abdf2cd9fc3fb766ee95eadd8d119cc9a78e9c00bbb159a8c2b547d9dfb5ab8cadd7fa83a5193f3"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
    $a3="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}