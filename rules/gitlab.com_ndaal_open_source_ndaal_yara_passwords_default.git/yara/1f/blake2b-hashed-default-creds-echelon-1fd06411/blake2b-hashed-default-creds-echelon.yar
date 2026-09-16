rule blake2b_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a1="bcad1d03c904223ac62a9850aa31b6af3468cc8f2820efad5f1b1c03710524df47f121462b234479d18be292a57940225ffc12c8a111825de7c4fdbca19f77e3"
    $a2="4bf4f3232214b372b598506b89b952a6af81ff193169f4cbfe1359a6cf90d77a6ff104050c04c1c17be03e6453127a8e7b4aea591f673219973075cc791c7df2"
    $a3="b192b944e41f8684230ab8c1ee2bfd190b9d5c759d6d40b28d6601b5a974c3a11f79b751b60bb14c1775b4aa99a64d308e984d4f2750064135eb0447456a33fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}