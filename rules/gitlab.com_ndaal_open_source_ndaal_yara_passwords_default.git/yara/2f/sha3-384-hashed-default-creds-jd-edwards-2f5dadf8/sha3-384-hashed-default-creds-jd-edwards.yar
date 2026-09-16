rule sha3_384_hashed_default_creds_jd_edwards
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jd_edwards."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="262ebc33bfdf58bd2e6537dba1c34f3fa7c528a5e560e3f7a79d90a5d44ced9bf76cab8a0cb34a73e735ca1c8b04efca"
    $a1="262ebc33bfdf58bd2e6537dba1c34f3fa7c528a5e560e3f7a79d90a5d44ced9bf76cab8a0cb34a73e735ca1c8b04efca"
condition:
    ($a0 and $a1)
}