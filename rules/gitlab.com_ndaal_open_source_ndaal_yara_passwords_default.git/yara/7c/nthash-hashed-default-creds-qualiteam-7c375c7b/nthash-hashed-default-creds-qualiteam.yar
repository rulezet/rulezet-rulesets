rule nthash_hashed_default_creds_qualiteam
{
    meta:
        id = "7a0G5J8efEkYkMAVMv2L2Z"
        fingerprint = "deeae3bd550f144ee073a2b0bee0db726f323de97b3b6970242946b9f5604548"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for qualiteam."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d3986e540a63647454a50e26477ef94"
    $a1="6d3986e540a63647454a50e26477ef94"
condition:
    ($a0 and $a1)
}