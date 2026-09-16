rule nthash_hashed_default_creds_open_xchange_inc
{
    meta:
        id = "7eCuh0nCQ7jqf3ulB0ebM3"
        fingerprint = "be93015217b5d684247c56fca7dd4415487cab58216b88c141d948cf28cdaba3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for open_xchange_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="878d8014606cda29677a44efa1353fc7"
    $a1="dec9eac14158ab414b2bac771f3d0376"
condition:
    ($a0 and $a1)
}