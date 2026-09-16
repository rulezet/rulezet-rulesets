rule nthash_hashed_default_creds_atlassian
{
    meta:
        id = "1I7WrlHTC2vv7O085Vq4cz"
        fingerprint = "afce9c608da0d1a140a8d91e55db6425adcc6038d31062c662078d3d8009d94e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="b8741d00cfaa40237c3bb7195ccc34a4"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="58e0f9d49806a4bedf29e3c368e4635f"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="46cd3aaad1927e1f85318ef93cb6cbdc"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="c2ea9f38c2f3a9644a08834efca06f70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}