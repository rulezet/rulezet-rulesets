rule nthash_hashed_default_creds_abb
{
    meta:
        id = "3wEXoFsEdtvWyepBSfMuof"
        fingerprint = "140d9da94ef9063fd905ec871782a3c543affe7a3eb0ffd254cd0edf60e7cbf1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for abb."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53997228bcf6e6ebc5fedbbba3fb6eb8"
    $a1="f07206c3869bda5acd38a3d923a95d2a"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}