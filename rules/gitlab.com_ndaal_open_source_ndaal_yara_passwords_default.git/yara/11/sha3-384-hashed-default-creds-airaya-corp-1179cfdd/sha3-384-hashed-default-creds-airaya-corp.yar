rule sha3_384_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="edc3bb91ca5640c94ecb2e6b34664fe76706382d93d457d5b3a3415257881599f577181613cd8a9272550eb76893f377"
    $a1="edc3bb91ca5640c94ecb2e6b34664fe76706382d93d457d5b3a3415257881599f577181613cd8a9272550eb76893f377"
condition:
    ($a0 and $a1)
}