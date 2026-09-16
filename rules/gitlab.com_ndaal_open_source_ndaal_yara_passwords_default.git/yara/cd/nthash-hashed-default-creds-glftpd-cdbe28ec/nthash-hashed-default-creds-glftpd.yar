rule nthash_hashed_default_creds_glftpd
{
    meta:
        id = "hyNEmDOmDkXCVi7WL9Ol2"
        fingerprint = "a2c0e42379688694aa3719a8f45d4178f637cb291da989e34ee46f0adc422043"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22fb8bfdb4097c43591e76812c6618d"
    $a1="d22fb8bfdb4097c43591e76812c6618d"
condition:
    ($a0 and $a1)
}