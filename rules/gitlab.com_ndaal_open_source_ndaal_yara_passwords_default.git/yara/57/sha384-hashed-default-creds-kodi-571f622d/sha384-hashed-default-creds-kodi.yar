rule sha384_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7ba5ce9b53888c18adcc0ddced9317bc555f1ecb4375e2d134d8ab5e8d12f7aff9c9e822e14c8575d74a68955e0ea23"
    $a1="e7ba5ce9b53888c18adcc0ddced9317bc555f1ecb4375e2d134d8ab5e8d12f7aff9c9e822e14c8575d74a68955e0ea23"
condition:
    ($a0 and $a1)
}