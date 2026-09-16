rule nthash_hashed_default_creds_bmc_software
{
    meta:
        id = "7JdGYv4RIayuxXqER2Jbbu"
        fingerprint = "5f4a7f7be1a59033b9a0a304f001b4dec1ac76f1a2ad41eab60740d022ecfeb0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f91cee88d21264dd25a205403894173f"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="b9d5be0831e32b9fdaf6e19f12e0814c"
    $a3="b5091f24d8feb0bf1649bbe9fae8251c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}