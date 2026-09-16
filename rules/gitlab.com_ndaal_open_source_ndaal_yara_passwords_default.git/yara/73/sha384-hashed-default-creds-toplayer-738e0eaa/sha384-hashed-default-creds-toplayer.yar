rule sha384_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="88fe00cc7a1ea381a17e7f76fc1dc8bc52594bf5b7155aafb35410f015f1a9aaf471b3e11be0302fcb3e3af409f9a655"
    $a1="435b65d39d2507f4e923e6de7efd729e361293351025e458e06d2bbbacf7260ecc7a5623d84e36eecab0af1238fb786a"
condition:
    ($a0 and $a1)
}