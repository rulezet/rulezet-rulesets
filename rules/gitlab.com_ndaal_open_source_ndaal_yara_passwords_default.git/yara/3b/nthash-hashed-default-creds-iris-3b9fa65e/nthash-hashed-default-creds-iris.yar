rule nthash_hashed_default_creds_iris
{
    meta:
        id = "4BmRWt75g28GnTgfcL7Cfr"
        fingerprint = "db5cfacd3e852e76d75278c78c97f99b31b54652eba84fc51682d7cec6be950f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iris."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0280777f37d4f4e7c478d21cec701463"
    $a1="d42a7e4ccf4197a5cea4f2de54a5fe45"
condition:
    ($a0 and $a1)
}