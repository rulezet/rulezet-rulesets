rule sha3_384_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c04cd0761d80e1894bbb709438c6c14b4e65cdaa82899d34907b049cbb98cf354161eec0b4f16a39c412edad867ec9"
    $a1="68c04cd0761d80e1894bbb709438c6c14b4e65cdaa82899d34907b049cbb98cf354161eec0b4f16a39c412edad867ec9"
condition:
    ($a0 and $a1)
}