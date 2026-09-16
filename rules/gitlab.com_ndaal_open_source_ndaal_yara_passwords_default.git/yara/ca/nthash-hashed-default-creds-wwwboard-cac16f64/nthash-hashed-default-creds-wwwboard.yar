rule nthash_hashed_default_creds_wwwboard
{
    meta:
        id = "16XIaYNuZwSkMG4pIl4c8J"
        fingerprint = "118fa725ff59819bd3ff63d3561c4484b3d676ff826fcec3c5762f20cea9bb91"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cdc328508bbd9e95f1ac010a432a3b6"
    $a1="af62387d97bc187df65ba77fa0d55881"
condition:
    ($a0 and $a1)
}