rule sha256_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="282a07ca6622ee1a0905ece84b4fd7208efdb66576669ac05425462b446bee05"
    $a1="fd4d53fe3f8b48ad75c7284e049507af5ef766bbe95c63b027b639639b09ec06"
condition:
    ($a0 and $a1)
}