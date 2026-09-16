rule sha384_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c4e647f27cf854985247bd1e2ee0bfe76de492c3a1420efd7870b0d688c117f749708c80d5da6b2e0762817f5940785"
    $a1="1c4e647f27cf854985247bd1e2ee0bfe76de492c3a1420efd7870b0d688c117f749708c80d5da6b2e0762817f5940785"
condition:
    ($a0 and $a1)
}