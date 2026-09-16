rule nthash_hashed_default_creds_promise_technology_inc
{
    meta:
        id = "5EU3r9DPONPB8US4N43Tdk"
        fingerprint = "734401f8b6a90b4722bfa3d47697c4777b52c5d5bb607c0f1a6e7d4240fcce00"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for promise_technology_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}