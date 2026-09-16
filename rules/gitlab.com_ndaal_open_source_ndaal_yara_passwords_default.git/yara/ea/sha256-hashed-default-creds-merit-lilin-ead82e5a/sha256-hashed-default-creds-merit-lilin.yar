rule sha256_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="298d81e0ac584433a17ef951d08f223c3ff8e8a16e5bed51f700408ae296584b"
    $a1="03494b0d1f803522a3497d751eaaf6f987883cd4fe0b0e66baf67a662ae231b2"
condition:
    ($a0 and $a1)
}