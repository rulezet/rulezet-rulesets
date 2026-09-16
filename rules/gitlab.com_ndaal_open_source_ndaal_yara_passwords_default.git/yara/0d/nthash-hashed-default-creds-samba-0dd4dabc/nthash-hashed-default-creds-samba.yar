rule nthash_hashed_default_creds_samba
{
    meta:
        id = "3KjCQKY9tBcOhJiea7t0Sm"
        fingerprint = "92b3472dcb9c855a433bbc9f5e38013c959e47c27c02a878de8efe5a8b99cfc9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d705a913bb120b86026c65c6a777da6"
    $a1="5d705a913bb120b86026c65c6a777da6"
condition:
    ($a0 and $a1)
}