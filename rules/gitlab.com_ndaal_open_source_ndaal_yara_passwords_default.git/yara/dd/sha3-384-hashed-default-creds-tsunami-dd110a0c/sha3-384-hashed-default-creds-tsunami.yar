rule sha3_384_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db4e5f8ca077e67b99cfb99fae79bcd0e66a4caca86a5f2ab1218ebc380ed3ad5864672cef70fe2559af2990c0c2abc5"
    $a1="db4e5f8ca077e67b99cfb99fae79bcd0e66a4caca86a5f2ab1218ebc380ed3ad5864672cef70fe2559af2990c0c2abc5"
condition:
    ($a0 and $a1)
}