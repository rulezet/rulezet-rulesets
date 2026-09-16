rule sha256_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29e8567beb99601ae9c07d77929d6e378590bbfc36499270614f788bdd6d1bb3"
    $a1="6ce5a26221cacd6e272a5ad95f109d0e7a0bc4419f2d979e597fc7e16b7467e3"
condition:
    ($a0 and $a1)
}