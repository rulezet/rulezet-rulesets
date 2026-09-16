rule nthash_hashed_default_creds_enterasys
{
    meta:
        id = "4qvb91eZ4kHSqPpnfQhM8E"
        fingerprint = "56e260ca1de520a09ff1d8763c1236e4ed793a525f29522374649c1f7ae899ff"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2003ea1b0309acb195f977cd6b66135"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="70772c5247dd98cbfc3700ff9acfa3ee"
    $a3="0b9957e8bed733e0350c703ac1cda822"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}