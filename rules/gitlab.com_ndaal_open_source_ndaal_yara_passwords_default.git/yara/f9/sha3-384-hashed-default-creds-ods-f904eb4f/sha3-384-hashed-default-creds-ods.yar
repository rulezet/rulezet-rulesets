rule sha3_384_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab3a37064c5a03d15eea29ebf71834a9abae7680763863b30e0f98f068d99276404f68f72bd6954b10e92bfd48f55ced"
    $a1="ab3a37064c5a03d15eea29ebf71834a9abae7680763863b30e0f98f068d99276404f68f72bd6954b10e92bfd48f55ced"
condition:
    ($a0 and $a1)
}