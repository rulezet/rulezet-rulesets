rule blake2s_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c87f12938122af1870b0ebda9f9064d6d882e1a43fbfb90819ea4e287d9b8ebb"
    $a1="d2f099740be00c8dd0971a63f041892d448cd7d1e396b37ddaaa938278b530fc"
condition:
    ($a0 and $a1)
}