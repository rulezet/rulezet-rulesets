rule nthash_hashed_default_creds_grandstream_networks_inc
{
    meta:
        id = "7IKba4qr4yn9reg3yy4FVF"
        fingerprint = "a8f36fb9e104fc3b45b84a005cc61a592978b2d03d05eee12fa434c4a21e4fe8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for grandstream_networks_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="3dbde697d71690a769204beb12283678"
    $a3="d4f99a69d277e45960f5add6039a856a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}