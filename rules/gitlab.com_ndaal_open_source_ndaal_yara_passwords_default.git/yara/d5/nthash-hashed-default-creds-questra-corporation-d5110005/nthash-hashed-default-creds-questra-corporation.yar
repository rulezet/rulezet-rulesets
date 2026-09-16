rule nthash_hashed_default_creds_questra_corporation
{
    meta:
        id = "11ETwtlbLvg3jSLBuSKXya"
        fingerprint = "9deffffee7ac8f02e971a726fab7eacfb8cca44cf85770b28866b21dde29412f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="823893adfad2cda6e1a414f3ebdf58f7"
    $a1="823893adfad2cda6e1a414f3ebdf58f7"
    $a2="4488413906518ae82b016fad4316dc4f"
    $a3="4488413906518ae82b016fad4316dc4f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}