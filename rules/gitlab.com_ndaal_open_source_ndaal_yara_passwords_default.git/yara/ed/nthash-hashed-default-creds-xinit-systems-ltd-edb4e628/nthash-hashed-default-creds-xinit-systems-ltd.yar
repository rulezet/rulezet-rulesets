rule nthash_hashed_default_creds_xinit_systems_ltd
{
    meta:
        id = "k2W6BfuVqWfiwuspG61r2"
        fingerprint = "993a9dc9467bfe94501610b51eb9fe18c38a1c8fc6c7d6eb439ba04f3da20f2e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xinit_systems_ltd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="df2633a81d336b0c3194ded9f7406210"
condition:
    ($a0 and $a1)
}