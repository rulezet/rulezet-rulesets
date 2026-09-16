rule nthash_hashed_default_creds_addpac_technology
{
    meta:
        id = "3JbfmA8XdQD7vdtdB4eTfr"
        fingerprint = "219c1392844713fbe271c33f80f159de4e35e384fa0c29eacc314b4a6a42a734"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for addpac_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd2351189d57d6cfde9e8f9cb96da06a"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}