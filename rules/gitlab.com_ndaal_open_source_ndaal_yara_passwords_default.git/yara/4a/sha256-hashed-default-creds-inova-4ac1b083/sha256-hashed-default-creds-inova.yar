rule sha256_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75fcdc79c50111d864ba4b79fafc57e12938f22c679916d67a7a5825cfa5b63a"
    $a1="479c139143a076ba9152751a266ee3817fd5ca70d46b143b25ee46504bd81928"
condition:
    ($a0 and $a1)
}