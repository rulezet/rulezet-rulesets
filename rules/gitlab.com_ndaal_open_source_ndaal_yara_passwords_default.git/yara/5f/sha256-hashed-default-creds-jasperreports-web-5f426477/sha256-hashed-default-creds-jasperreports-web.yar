rule sha256_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="017fbc0e001b5e9c16908c754f9607dc886f25d08b2cbadc788b8b267df199f2"
    $a1="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a2="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a3="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}