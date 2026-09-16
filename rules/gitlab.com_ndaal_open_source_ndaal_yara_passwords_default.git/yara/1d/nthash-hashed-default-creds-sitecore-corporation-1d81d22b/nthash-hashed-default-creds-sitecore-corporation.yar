rule nthash_hashed_default_creds_sitecore_corporation
{
    meta:
        id = "4C3yidBQG2aB8VabTSToZn"
        fingerprint = "a315c09d4f68268b0cf024985f324025dced36b7abf6f61a20cc90b4dbc211b3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a047ee4a9db8bc8b4f3f8a03d72deb80"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="186cb09181e2c2ecaac768c47c729904"
    $a3="f5aa35c276762e778705c190fd3e9918"
    $a4="a047ee4a9db8bc8b4f3f8a03d72deb80"
    $a5="05627fdc6968530000274506b0e3b156"
    $a6="9b75cf9a3fcc498e03eeda4387bb5277"
    $a7="4ff0fda1e875aee48955cd5283f56dac"
    $a8="449d05cc4b34c94e21558281885b066e"
    $a9="7e33bfd06323cfa990580fad4b7901f9"
    $a10="7e864d8195b263b4d6aee4e041c0193f"
    $a11="07c98ffabe63ff15d88d74dc035fcdf5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}