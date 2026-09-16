rule sha3_256_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5e45898eda7cc4ee72bd501fae366cd68d0a6761c9a505fc9efc5634abfbff6"
    $a1="d5e45898eda7cc4ee72bd501fae366cd68d0a6761c9a505fc9efc5634abfbff6"
condition:
    ($a0 and $a1)
}