rule nthash_hashed_default_creds_brocade
{
    meta:
        id = "6yhcl5P9WGNKmAEGPKIb9s"
        fingerprint = "6991a57caa440c2d68482e1bfed405fb8ac53da1f65abbaaa8d10080d78cf277"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b43c5086e6c85a0467a43e90bf9b1a47"
    $a1="3de69f85ba8907f7500e08cf8e55e33a"
    $a2="93353515f03f0b5df0a0dd95d14e758d"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="57d583aa46d571502aad4bb7aea09c70"
    $a8="fcd66bf120173b2eb6756a12f8ecc4bd"
    $a9="329153f560eb329c0e1deea55e88a1e9"
    $a10="231c5241c2a2228dffa06b71faec3995"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="97babab85ab61fff0136846617602e0a"
    $a13="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}