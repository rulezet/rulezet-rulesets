rule sha256_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15a596e3c98c407e043751ff3b21ff0358a1bdfdf3fe948b1523893a8e5de2e8"
    $a1="5f2c4152d00cac63465da6225818c6ba60f7ede77c0e759f16f1eb4eec5927ba"
    $a2="15a596e3c98c407e043751ff3b21ff0358a1bdfdf3fe948b1523893a8e5de2e8"
    $a3="b9fcc14006622476f1840fde6bf0eec264761d0536f287278755254e76a78061"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}