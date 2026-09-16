rule nthash_hashed_default_creds_kodak
{
    meta:
        id = "2X8kX6FSJJlFJNVfOOj41J"
        fingerprint = "96febb90aa4b9ac8bf94e2abcc6df7e2772026da6de374495f86168613069032"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24a00b67c3feb64064c348a370cc3b1f"
    $a1="f4c36945cce5c05a9d6b4531dff36dbf"
    $a2="24a00b67c3feb64064c348a370cc3b1f"
    $a3="8c2ea3a7b69ce9fa94f41881087667a4"
    $a4="24a00b67c3feb64064c348a370cc3b1f"
    $a5="516eb4ef252396110a96e7e7dfa5c5fb"
    $a6="7b592e4f8178b4c75788531b2e747687"
    $a7="d697885efa5d17b05c9449e0636dea11"
    $a8="8a68981fb3d9befdb6f440f137324546"
    $a9="8a68981fb3d9befdb6f440f137324546"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}