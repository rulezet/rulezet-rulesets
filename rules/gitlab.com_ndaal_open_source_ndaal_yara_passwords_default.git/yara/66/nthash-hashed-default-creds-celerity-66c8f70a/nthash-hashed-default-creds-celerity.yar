rule nthash_hashed_default_creds_celerity
{
    meta:
        id = "QVBJtt14chqUx5i8pmjcL"
        fingerprint = "d3875a240d4dd79dedf7b4d4d0c2535ba0063819b73fd7cc08923cbf9b8b7ed4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5a4e3f7926ead1808de5437067d9f78"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="76b73ff4c9f1974401351eac9887e6d2"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="9e3927efcb1155a64ae6cd92af47ee84"
    $a5="9e3927efcb1155a64ae6cd92af47ee84"
    $a6="09f151785872f8ba88c62604d1e355f0"
    $a7="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}