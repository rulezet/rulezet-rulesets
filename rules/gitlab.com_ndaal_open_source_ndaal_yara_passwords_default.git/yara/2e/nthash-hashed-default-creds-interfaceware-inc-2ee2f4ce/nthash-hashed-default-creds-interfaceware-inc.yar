rule nthash_hashed_default_creds_interfaceware_inc
{
    meta:
        id = "6KkDj9GDQN5rzPk8FJvdmY"
        fingerprint = "0a9c1cef9874571bd2e8e6c2de233281c13518f555671778c1d9ddab8ea21abc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interfaceware_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="9ca10ea058b7d57acc3937e1d99b5904"
condition:
    ($a0 and $a1)
}