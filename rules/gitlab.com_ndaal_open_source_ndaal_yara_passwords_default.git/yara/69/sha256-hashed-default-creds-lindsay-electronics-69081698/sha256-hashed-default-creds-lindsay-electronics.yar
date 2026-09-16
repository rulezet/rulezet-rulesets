rule sha256_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
    $a1="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a2="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
    $a3="6a0214473ea95fc4e02fe7079c3e34eed01836faa2cc729394f8b1a5b6e65dc3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}