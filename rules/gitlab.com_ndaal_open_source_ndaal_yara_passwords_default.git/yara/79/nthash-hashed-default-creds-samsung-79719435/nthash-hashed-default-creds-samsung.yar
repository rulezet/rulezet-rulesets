rule nthash_hashed_default_creds_samsung
{
    meta:
        id = "1xjXwtS2oBU0VcrAeGczVs"
        fingerprint = "c7baac4d57ae316c5018a55be4cc3f8c689aea19b644f12e79498c3a036aa619"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09a544c2d58253db6f3613ec0597dc47"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="db51013b2730e1f16df6db7c3a73ad60"
    $a3="db51013b2730e1f16df6db7c3a73ad60"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="e3e90ed69a2af487ac8bc5c55dd4ee35"
    $a7="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}