rule sha3_384_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1122a2e3f0d239d93ff35f517203de2b7c2d8b93d33596c8dd5ba283c1468e9c9adce1a8ad9abd7cfa0ffbf090fa407b"
    $a1="1122a2e3f0d239d93ff35f517203de2b7c2d8b93d33596c8dd5ba283c1468e9c9adce1a8ad9abd7cfa0ffbf090fa407b"
condition:
    ($a0 and $a1)
}