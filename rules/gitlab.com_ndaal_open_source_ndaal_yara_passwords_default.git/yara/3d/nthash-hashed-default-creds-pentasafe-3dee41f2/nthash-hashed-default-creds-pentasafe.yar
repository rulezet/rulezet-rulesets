rule nthash_hashed_default_creds_pentasafe
{
    meta:
        id = "36DGG27mlaMHlEQU2BAgxw"
        fingerprint = "50ecc52c512b756317bfb1eda66379a7b69db90d84f0f37075724fbaacb15c8f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53f7294c5b0555d0235839aa7f1106c4"
    $a1="7f93957f8a61679512bfb7fe4464af88"
condition:
    ($a0 and $a1)
}