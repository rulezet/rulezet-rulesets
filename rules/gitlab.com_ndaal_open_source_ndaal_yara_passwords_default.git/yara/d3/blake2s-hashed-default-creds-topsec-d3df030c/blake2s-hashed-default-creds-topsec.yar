rule blake2s_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fd7c852306bc9e7c6c59441be9980367fa8f65c6ab908ad7ddc416ad49ee2a1"
    $a1="9495af2bfd7926e8a8cdb642728a3b728f9500dd99343995c7262d37b023884c"
condition:
    ($a0 and $a1)
}