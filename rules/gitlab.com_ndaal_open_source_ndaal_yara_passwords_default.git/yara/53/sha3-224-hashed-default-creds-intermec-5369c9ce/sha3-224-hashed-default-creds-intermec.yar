rule sha3_224_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
    $a1="fa5853427d8241a235fe881a298d29d3c0654eccc2be64f9110db31f"
condition:
    ($a0 and $a1)
}