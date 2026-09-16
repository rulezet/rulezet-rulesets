rule sha224_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a6a900c5d7d1e2af4bca459a8cb64fc291ab877662ce19321f5cb67"
    $a1="74cf1b20bb5eb3edd11ea546fb7877010f06424fac89d6d7a18f7337"
condition:
    ($a0 and $a1)
}