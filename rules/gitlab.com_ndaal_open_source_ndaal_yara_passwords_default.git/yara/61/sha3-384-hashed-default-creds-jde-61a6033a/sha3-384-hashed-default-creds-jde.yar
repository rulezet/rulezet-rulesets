rule sha3_384_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e666d206603b2e11a291ca65490e0fe52016a752f5c217015908fac53779154e1555b5d6b9f54b43c1eb05c27f72e96"
    $a1="5e666d206603b2e11a291ca65490e0fe52016a752f5c217015908fac53779154e1555b5d6b9f54b43c1eb05c27f72e96"
condition:
    ($a0 and $a1)
}