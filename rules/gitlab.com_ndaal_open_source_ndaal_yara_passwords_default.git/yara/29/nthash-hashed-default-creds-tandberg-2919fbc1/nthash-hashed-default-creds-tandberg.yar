rule nthash_hashed_default_creds_tandberg
{
    meta:
        id = "156mpo3bIlRbBsLEPI2oaO"
        fingerprint = "405ddde9a25c6706491d02b830f98dc81903f30ea340fd942668e0eabdee7885"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandberg."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c7d612f368af69dd6afaca75756aa59"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="0c7d612f368af69dd6afaca75756aa59"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}