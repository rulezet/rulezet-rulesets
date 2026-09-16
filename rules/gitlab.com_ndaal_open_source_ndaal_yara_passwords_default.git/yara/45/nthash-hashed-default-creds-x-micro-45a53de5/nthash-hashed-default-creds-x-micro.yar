rule nthash_hashed_default_creds_x_micro
{
    meta:
        id = "fZ97n44MD9RRQCnXWZuSM"
        fingerprint = "67f28956c13f020f0a787f27a66f0a2819ec682d92957317552917a9eca093d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fad2607eda55ca3ecf8d89067ee91f84"
    $a1="fad2607eda55ca3ecf8d89067ee91f84"
    $a2="201f4542b52d54a6b7a89f31f3e109eb"
    $a3="201f4542b52d54a6b7a89f31f3e109eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}