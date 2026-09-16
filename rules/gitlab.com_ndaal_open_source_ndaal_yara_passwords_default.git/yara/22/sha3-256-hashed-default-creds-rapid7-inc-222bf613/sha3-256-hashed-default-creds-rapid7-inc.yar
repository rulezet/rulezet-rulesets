rule sha3_256_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f16c20fca544f15382e94bcd390bf04ac0ff74016d49ccc2916597271444ee4"
    $a1="2f16c20fca544f15382e94bcd390bf04ac0ff74016d49ccc2916597271444ee4"
condition:
    ($a0 and $a1)
}