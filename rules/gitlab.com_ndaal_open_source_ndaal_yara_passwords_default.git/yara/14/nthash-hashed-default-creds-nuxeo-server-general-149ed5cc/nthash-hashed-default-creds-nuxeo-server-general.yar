rule nthash_hashed_default_creds_nuxeo_server_general
{
    meta:
        id = "7A7TvlYsAiRwI4XxdScIgn"
        fingerprint = "97111d23f1dd40ad347a42b3c8f6c3b78bfd0516eecb17380b64bcd71bbf820b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nuxeo_server_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d144986c6122b1b1654ba39932465528"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}