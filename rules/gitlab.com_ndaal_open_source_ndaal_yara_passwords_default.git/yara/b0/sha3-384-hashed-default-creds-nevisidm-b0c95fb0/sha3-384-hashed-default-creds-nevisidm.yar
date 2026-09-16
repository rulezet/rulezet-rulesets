rule sha3_384_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81a85f11bf623a5812e633428bd5de3a97be512bf05711ae4838e14fb694d691200499ea5a87c9ef8dcbd109f805ecc7"
    $a1="036d97795c39019b373dd89e9aead59640cce2158e39851b4080c2215117180924cf1b83ddcbd34b9189eb380809812c"
condition:
    ($a0 and $a1)
}