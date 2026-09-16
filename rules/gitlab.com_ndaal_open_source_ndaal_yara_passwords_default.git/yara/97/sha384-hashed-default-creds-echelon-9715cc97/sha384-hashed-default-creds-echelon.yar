rule sha384_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a1="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a2="7c5965f7106a8cf01d45360fdec51568189b9a0b3bf69b90f2a978c303819d82701e3aed9aa512e41f9d12bae4d21f8b"
    $a3="e757449617a5368e0ae8982d59e258a820e72fcacb7d71ed6b69e0c6eb28c6a7e4cc530626dd1023293239c403023998"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}