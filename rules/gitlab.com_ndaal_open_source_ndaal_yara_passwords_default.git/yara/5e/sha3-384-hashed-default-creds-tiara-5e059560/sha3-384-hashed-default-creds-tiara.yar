rule sha3_384_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eac570c2e6e211425a60e32cb04ec6da7b626126dc7bf1b8aad33ce166d1b9f2ba83d6354a430d461ee0bbf78a6c3bc9"
    $a1="e619b85b927015fe24086cb9b22540eef895d6b4b87179bfd9d4911d90a388ea6594cb13f811bc6e3b86d8e15d1046db"
condition:
    ($a0 and $a1)
}