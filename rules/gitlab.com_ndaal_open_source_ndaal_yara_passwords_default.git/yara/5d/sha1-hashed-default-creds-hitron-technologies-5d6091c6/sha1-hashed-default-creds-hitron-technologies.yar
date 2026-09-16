rule sha1_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="3e3932104337c1d92dc3052dfaf41103af17d1c5"
    $a3="3daf2f47b842e807082c74acfaa06b7286cb6dcb"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="8f198fad85c1ade2c1fa575158726672d789eeea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}