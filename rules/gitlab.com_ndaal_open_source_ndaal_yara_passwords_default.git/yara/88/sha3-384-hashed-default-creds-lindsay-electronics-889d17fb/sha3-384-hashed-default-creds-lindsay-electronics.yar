rule sha3_384_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
    $a1="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a2="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
    $a3="8932ace6c9d3fa73f7ff5701e6fd36dc6d7679090b6d3e2c094b9b2d0dbaf8e6e6c93471d51e5d9e5c1d9a9fabf89590"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}