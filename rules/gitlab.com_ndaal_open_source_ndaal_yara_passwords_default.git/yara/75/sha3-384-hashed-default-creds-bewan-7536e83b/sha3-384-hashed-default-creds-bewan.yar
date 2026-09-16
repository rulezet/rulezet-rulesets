rule sha3_384_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58dc5ffa280630891231e145f331ed8984d7ad4f989856cb8765aa50132b08aaca634b9bbca0abaee97dd2642b87180b"
    $a1="58dc5ffa280630891231e145f331ed8984d7ad4f989856cb8765aa50132b08aaca634b9bbca0abaee97dd2642b87180b"
condition:
    ($a0 and $a1)
}