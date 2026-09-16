rule sha512_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="67726cd98cc5ad4db112664ffe2942cc9c8ec559f75d2d321c32db88b9a31af0c97abb8afa216da9c3c8131769594a8b2f39d438e75b3a76472585253b1d0143"
    $a1="67726cd98cc5ad4db112664ffe2942cc9c8ec559f75d2d321c32db88b9a31af0c97abb8afa216da9c3c8131769594a8b2f39d438e75b3a76472585253b1d0143"
condition:
    ($a0 and $a1)
}