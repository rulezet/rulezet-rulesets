rule blake2s_hashed_default_creds_lockdown_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lockdown_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a022c3331d7a613c4e57634e7332ab6cf8b8fffd03071b393c8b8977dbd04233"
    $a1="b78b08cff2216891738ec4218298c908949df667f4de983be128fd9c14b1c279"
condition:
    ($a0 and $a1)
}