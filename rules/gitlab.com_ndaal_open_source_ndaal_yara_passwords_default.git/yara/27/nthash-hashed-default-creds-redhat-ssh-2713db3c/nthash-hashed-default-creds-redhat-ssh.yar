rule nthash_hashed_default_creds_redhat_ssh
{
    meta:
        id = "6jvUdEzkQGB9HapJZJFEVI"
        fingerprint = "3bebeb28f75cdeb7abf9f12ed1ef61c852dd099c26f2dd79f15653ae5063170c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="5ff233ecf5526941e22a0766d926d79a"
    $a3="5ff233ecf5526941e22a0766d926d79a"
    $a4="64f92a7257f6e6e48d2be10daa793463"
    $a5="5ff233ecf5526941e22a0766d926d79a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}