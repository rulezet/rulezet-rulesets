rule blake2s_hashed_default_creds_bmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76ef2cedafd9d332a98d5962e03a89e5edc4b8af423aad2d7db73727829ea8c2"
    $a1="76ef2cedafd9d332a98d5962e03a89e5edc4b8af423aad2d7db73727829ea8c2"
condition:
    ($a0 and $a1)
}