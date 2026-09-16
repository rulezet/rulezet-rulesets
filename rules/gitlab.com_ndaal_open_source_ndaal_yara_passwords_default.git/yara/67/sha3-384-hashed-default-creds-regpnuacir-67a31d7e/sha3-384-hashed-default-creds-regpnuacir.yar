rule sha3_384_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="833f2b67dc4ca68257c7613202b75cf45439036d2b88f4a7a02ca9430418f3fc8f2fe4e371aa83cda2812ceb51fc9e48"
    $a1="f5df22fa097933f4c11acdefaf7eefa936c9dd136cae8cdd4b3fcb1ab85a1657bc106e7460812bcd996c65c57d96594c"
condition:
    ($a0 and $a1)
}