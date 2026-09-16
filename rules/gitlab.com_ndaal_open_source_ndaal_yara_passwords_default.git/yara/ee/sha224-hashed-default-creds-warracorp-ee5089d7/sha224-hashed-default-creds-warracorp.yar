rule sha224_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15f5bc8fd57b7ab48a8666a44b337bfceba30e74b6443b17c8ae6e32"
    $a1="15f5bc8fd57b7ab48a8666a44b337bfceba30e74b6443b17c8ae6e32"
condition:
    ($a0 and $a1)
}