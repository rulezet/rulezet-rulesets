rule sha3_384_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37c2b4141680be6187b9b40d80f5c03466c5c0627a193dc2587b7dc27444fb0e1e270f85c2002b50aebdc6f633416ae4"
    $a1="0a7454e6283787a6094d5d18a41ae5d9df58c6923bd483182d391a6fe6f5e177ff0004774c5e341d32b07e5701d89528"
condition:
    ($a0 and $a1)
}