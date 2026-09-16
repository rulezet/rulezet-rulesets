rule sha3_512_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76e4a5dce3971027fb573f48dec3cabbd3946f635c9bed91812d0f99a14178551db0999135016f8b03d9949f03f49b4f6f6aba120b178aae6d5aad38192bc4bf"
    $a1="76e4a5dce3971027fb573f48dec3cabbd3946f635c9bed91812d0f99a14178551db0999135016f8b03d9949f03f49b4f6f6aba120b178aae6d5aad38192bc4bf"
condition:
    ($a0 and $a1)
}