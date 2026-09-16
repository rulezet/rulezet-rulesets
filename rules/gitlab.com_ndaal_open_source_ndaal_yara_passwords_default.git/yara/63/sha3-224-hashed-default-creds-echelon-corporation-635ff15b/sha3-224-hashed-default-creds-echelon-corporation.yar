rule sha3_224_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
    $a1="f0ee18d48831bf830553f88ec9ad9c8dd3b81a8016620d68f34039a3"
condition:
    ($a0 and $a1)
}