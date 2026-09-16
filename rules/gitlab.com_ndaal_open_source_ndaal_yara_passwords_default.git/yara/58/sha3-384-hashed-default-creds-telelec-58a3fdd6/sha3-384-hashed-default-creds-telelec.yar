rule sha3_384_hashed_default_creds_telelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telelec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a31a9d3ef8e51ecba10bbf97fdb7ed9c08e0378c4905027e7526d6607e35e609143b54f0c9cdaceac33aba62c2b6c34b"
    $a1="a31a9d3ef8e51ecba10bbf97fdb7ed9c08e0378c4905027e7526d6607e35e609143b54f0c9cdaceac33aba62c2b6c34b"
condition:
    ($a0 and $a1)
}