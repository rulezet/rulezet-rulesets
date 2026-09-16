rule sha512_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
    $a1="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
condition:
    ($a0 and $a1)
}