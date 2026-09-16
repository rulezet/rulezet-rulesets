rule sha3_256_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28e07df0e9f653279d31423f050874fae0e43e262e8ba6e31ce191f0a29e9b02"
    $a1="a2295409551cd5b997929fa15de81b5c46d24778d7d47fddf78d1619895a94f2"
condition:
    ($a0 and $a1)
}