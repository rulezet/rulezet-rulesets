rule nthash_hashed_default_creds_ibm_urbancode_deploy_web
{
    meta:
        id = "2pyPzrUKo7dnBqUo86ioQG"
        fingerprint = "6f5d30f68a6db8e1ccc95e0846974429a2c699d6f4e79bd8de6194d28f6faa84"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_urbancode_deploy_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="689feb4591fd23b1cde7334527e49c36"
    $a3="689feb4591fd23b1cde7334527e49c36"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}