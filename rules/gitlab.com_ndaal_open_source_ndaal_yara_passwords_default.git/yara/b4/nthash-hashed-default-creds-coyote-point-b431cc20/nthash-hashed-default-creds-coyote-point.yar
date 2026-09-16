rule nthash_hashed_default_creds_coyote_point
{
    meta:
        id = "57djTDECNw8qlTYxzdg48"
        fingerprint = "d02f09ea4a28ba3901c8edbe3ac077710a309b1166839b82cfbe142e43f3f66e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5f3bcdcddbe2441402dedcfafb78d00"
    $a1="9d4bba55537c63b5202dc974f798ec4e"
condition:
    ($a0 and $a1)
}