rule nthash_hashed_default_creds_datawizardnet
{
    meta:
        id = "86qQPiYLe6TqBdFiXrpmG"
        fingerprint = "8c5e0897f281d2b1b1b9c523e610e60d81e744eedcdb30682109795c94367f98"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fe23b5193b4d36aa86cba6e27883e1c"
    $a1="4481b934fc9cad79cb0f5295fa8cfc98"
    $a2="724279aa825e91ca54a5cc1db868bd4d"
    $a3="4481b934fc9cad79cb0f5295fa8cfc98"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}