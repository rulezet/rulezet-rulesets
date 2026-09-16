rule sha256_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd0624d77f522eac19f103b7e22f69b46e3d5d37cce09288d7b1dfb130885ed0"
    $a1="cd0624d77f522eac19f103b7e22f69b46e3d5d37cce09288d7b1dfb130885ed0"
    $a2="acdaf6b9d19088c668b4ac71c8f97f28e70c8ce6e7839ca99d49293a12d52756"
    $a3="ba1625a37ecad107990e31208789f5fec017b6e9e6f422778139e8f872aa5518"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}