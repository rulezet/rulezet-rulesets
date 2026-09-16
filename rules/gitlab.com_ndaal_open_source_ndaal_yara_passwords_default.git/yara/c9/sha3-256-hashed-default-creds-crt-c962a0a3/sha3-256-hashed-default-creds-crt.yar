rule sha3_256_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="680130426ecff5860a526f7ec156cb4f6fc41ddd0a3b271010753a0900610dff"
    $a1="7f73672fbffe44a89b1c6ab318ccadd20db8333e1ddc63d6fea69346b68ac6a7"
condition:
    ($a0 and $a1)
}