rule blake2b_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="052f738318a08384330a6b54c4a4ee7b637429bc655871f738a35068361147eabb258d19b29e99dec35710ae386310b5f19ff1c9179be4258bd1734b497923f8"
    $a1="91f3a5c40c87651bdd2383f5b5e90dd1a6e0178cd3e8e7b2113340e7bf192506b5c03fb06720c575936796bc6199c405b98ef2d00449a813bc860fbb3b0d34e9"
condition:
    ($a0 and $a1)
}