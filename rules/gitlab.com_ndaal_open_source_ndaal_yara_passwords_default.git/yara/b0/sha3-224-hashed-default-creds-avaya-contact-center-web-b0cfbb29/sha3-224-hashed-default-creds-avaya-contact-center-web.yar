rule sha3_224_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
    $a1="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
condition:
    ($a0 and $a1)
}