rule sha3_512_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
    $a1="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
condition:
    ($a0 and $a1)
}