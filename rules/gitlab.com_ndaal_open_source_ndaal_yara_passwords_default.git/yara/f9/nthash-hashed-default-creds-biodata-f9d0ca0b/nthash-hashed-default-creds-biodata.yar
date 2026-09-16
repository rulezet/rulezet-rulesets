rule nthash_hashed_default_creds_biodata
{
    meta:
        id = "56zN9esEbOb1ocAV0Uwtx3"
        fingerprint = "234c2f00702beaf1d26687fba2c4928f193a2263cb0d29e8dbfef9770ac6c43b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcec1b476c09a3ff3204e149ac00c00a"
    $a1="c8289b04dd80da2a24cb03cf3b41e1b6"
condition:
    ($a0 and $a1)
}