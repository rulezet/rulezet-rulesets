rule sha3_256_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bcbc31574e376353de7b4fa2a9b895635e8129e6e49d61878076cba39b50dd0f"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
    $a3="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}