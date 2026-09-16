rule sha224_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55c9f49baad49f1bdd9415654f3ff31e8903900d33a5564940d029ba"
    $a1="3c1b886c848af7694daa1bfffbbd67d24d0849fc6de995130b25b077"
condition:
    ($a0 and $a1)
}