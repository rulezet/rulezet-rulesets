rule nthash_hashed_default_creds_carestream_health
{
    meta:
        id = "6srXasmUxnvR5JqGQPK4Lf"
        fingerprint = "dd11fd805c8a841ffd6aac8ccdd60671334436282a72b2161d031177f332d30f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d29c152c66abda85ee8332133d6a5b67"
    $a1="2d4a34f4dbe4e116623d85db8680d7f1"
    $a2="d29c152c66abda85ee8332133d6a5b67"
    $a3="72cba7b1195e07498ff65ce0f15aa205"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}