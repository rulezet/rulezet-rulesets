rule blake2b_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6462f2c64a1382bbfa3973dc9527c3cce7ad1c4d616c64114bb3ecbe3a9f5077da0569949b9658b1acf6ddda67bd28f21029d46704e13753498ed61cc75a9827"
    $a1="dc41e431fac045f3ed6543dbefada68bfcf639d47c099778321ab5148a9f74e08081581f0c91a2300c78903f1d57c16f2123eaa34a6d7342e9a1cd5604aecf59"
condition:
    ($a0 and $a1)
}