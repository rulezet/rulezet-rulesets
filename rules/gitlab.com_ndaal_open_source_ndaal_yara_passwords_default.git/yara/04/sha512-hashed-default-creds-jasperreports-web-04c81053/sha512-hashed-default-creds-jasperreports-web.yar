rule sha512_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d99824d0cb6804c4996fc34f06ab2563de34e851f0c3fc25a2c0cc632b12ab2ad63dd4a6cbe39e4105ec08d6f6e5d5fc799dd70a3ab47ad83aa584febda5d5b"
    $a1="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a2="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
    $a3="ea1053d265ca4ec96319f3ee4dfffaf4e436e09c857337024d7cad5b07a6a79d0bcf71031b35a5afd99559f0b70db1e562aabaf0f0b26c7081a2fe91a352d591"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}