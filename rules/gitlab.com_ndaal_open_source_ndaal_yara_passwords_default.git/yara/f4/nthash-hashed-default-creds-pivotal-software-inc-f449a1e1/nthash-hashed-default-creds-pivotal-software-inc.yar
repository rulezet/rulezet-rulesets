rule nthash_hashed_default_creds_pivotal_software_inc_
{
    meta:
        id = "2ggslXaMbYyvPtX40TlEId"
        fingerprint = "aae5dc06d06d5a1cade7dee0369996b8e51b63ae590065edfba07b2d6ab03e9e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pivotal_software_inc_."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="823893adfad2cda6e1a414f3ebdf58f7"
    $a1="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1)
}