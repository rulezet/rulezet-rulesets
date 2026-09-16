rule sha3_256_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="362d9bc29a188856d30b9c2fcfc4dde7dfbca9a22b415aee884d471bb4074327"
    $a1="362d9bc29a188856d30b9c2fcfc4dde7dfbca9a22b415aee884d471bb4074327"
condition:
    ($a0 and $a1)
}