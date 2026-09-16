rule sha3_512_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d93817071b62f94cbcd35d060ab3aa44c76910e96d25da18043dda006035827c98cd53eea944760af8970913c1aba72697008928cd1dfc4e314d30c3f613cb1e"
    $a1="ea2075ec83ffbce8a318373ee69e45720fc5870a00ed697489ab4557202338c4595840f5b864cebf3331398ff6d3da143456b22a886530a472d75871caf08ecc"
condition:
    ($a0 and $a1)
}