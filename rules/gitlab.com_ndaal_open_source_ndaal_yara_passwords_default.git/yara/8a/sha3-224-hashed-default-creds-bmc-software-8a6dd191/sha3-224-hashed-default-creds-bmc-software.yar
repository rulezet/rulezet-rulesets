rule sha3_224_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d3a5480e48af890f8480168a5ab4c9bfda130686b4f9c773de3b120"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="4ef56d89c836b63396d348184cc3cc5b2c74fcd0303dd25d6c3d9c1c"
    $a3="823d5428f2e78f4e178af81b6aff297103a8491d0326960efe930fdb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}