rule sha3_224_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2121be558996192813a468a057809e53ad07b0f395781a2315c03b28"
    $a1="0a2d0d775dae3c3d1c55d3f5b54f6a766124938eb25435203082aada"
condition:
    ($a0 and $a1)
}