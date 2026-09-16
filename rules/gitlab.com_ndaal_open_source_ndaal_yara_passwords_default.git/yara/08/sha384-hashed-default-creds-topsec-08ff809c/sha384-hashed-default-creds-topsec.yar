rule sha384_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64273dab139fa4eb8926cd7fe0a81c4c1d901d46f4c4ebd9b03eb90e3eacbba9d12ca377ae4054ef860b4520cb1b70b7"
    $a1="584b3ffccb64d43929696d4023daefd6a92c9744d8c56a4e1213704692cc02078f0c27f73dc975669ce1922da0a5e5d6"
condition:
    ($a0 and $a1)
}