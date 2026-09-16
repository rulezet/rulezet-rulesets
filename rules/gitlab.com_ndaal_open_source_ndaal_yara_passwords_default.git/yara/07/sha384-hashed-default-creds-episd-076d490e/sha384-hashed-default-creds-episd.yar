rule sha384_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d19c666186eb160ee654293a743256ccb20d0897888d7d4dcb6a2968652220fa192686d1381d9bb19ee556030e7f6c0"
    $a1="dbaf470e968c60a318904e61145c6e4c18be449fc891661a7445f852194f48e413c8a170ba27fc89ae4680a93aaf3fef"
condition:
    ($a0 and $a1)
}