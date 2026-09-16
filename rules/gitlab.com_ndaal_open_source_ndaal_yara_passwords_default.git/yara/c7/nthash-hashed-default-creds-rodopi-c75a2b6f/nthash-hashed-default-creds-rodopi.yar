rule nthash_hashed_default_creds_rodopi
{
    meta:
        id = "44GyXe5WmH7MPbueu8Fhc2"
        fingerprint = "2936af38d3ccd53f01e85ab7e4cdefe98be117b4e98ac6963644f8a19a77bda0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2aea23ed4096af1f55ceb2b30c74802"
    $a1="e2aea23ed4096af1f55ceb2b30c74802"
    $a2="b4ae0d00cd8d8f612664e85400974938"
    $a3="b4ae0d00cd8d8f612664e85400974938"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}