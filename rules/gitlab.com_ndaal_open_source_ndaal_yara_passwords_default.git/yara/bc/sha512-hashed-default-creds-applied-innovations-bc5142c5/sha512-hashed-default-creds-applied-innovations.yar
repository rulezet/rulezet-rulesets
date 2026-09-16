rule sha512_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c0410db0dd79433438f9e19950dc9ca5e49f822010e3d63f30afd64e7a25ffd7b1839319819f9c9a1c4c56a15ffdbd96958a12d8c11afcc56b59e7328ac791c"
    $a1="4c0410db0dd79433438f9e19950dc9ca5e49f822010e3d63f30afd64e7a25ffd7b1839319819f9c9a1c4c56a15ffdbd96958a12d8c11afcc56b59e7328ac791c"
condition:
    ($a0 and $a1)
}