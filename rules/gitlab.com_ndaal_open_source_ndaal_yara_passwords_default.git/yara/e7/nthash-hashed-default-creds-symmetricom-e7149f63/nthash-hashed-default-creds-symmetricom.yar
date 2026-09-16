rule nthash_hashed_default_creds_symmetricom
{
    meta:
        id = "5XeEWfI4ckH74q3cPAxGZz"
        fingerprint = "4185b2a4ef95965657f35bd2ea9ca8307cdd644e986013b5d864393e91c66e19"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd422fc4357c1dbcd8e3a03071da79d6"
    $a1="823893adfad2cda6e1a414f3ebdf58f7"
    $a2="3d17c1d431b130eb1ca0cc03306e1ba9"
    $a3="e337e31aa4c614b2895ad684a51156df"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}