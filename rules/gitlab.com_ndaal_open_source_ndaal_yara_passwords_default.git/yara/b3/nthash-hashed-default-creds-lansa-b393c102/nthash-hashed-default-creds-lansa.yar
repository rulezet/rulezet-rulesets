rule nthash_hashed_default_creds_lansa
{
    meta:
        id = "5XnSQvNquQcn8BZCOHgFEx"
        fingerprint = "661027a4b9dde73e259330eddf8eebd65b47f834e22eaef852cb92b63952595e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="0df5244b85806f3154907a58d7765f91"
    $a3="0df5244b85806f3154907a58d7765f91"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="44ca85566cecbd32a06084ad8bb61a80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}