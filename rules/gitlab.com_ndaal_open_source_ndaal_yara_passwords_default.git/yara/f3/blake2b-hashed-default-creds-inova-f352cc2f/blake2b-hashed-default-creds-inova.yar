rule blake2b_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f08602bc6c930eea3995af11a78fc4e6d5f90ebf6d8f7c982f0b06ab7c5a15fdb25ad67a92783e46d5bc3cedf32f6da05d867d12a65b398fd6b223fe0ce69f16"
    $a1="14a70e1680168058dab8e17a804182d1ce7ed4e58aaf0462b370c4db80bfab0d43ec07690f77f45e94a4bae11521c68a3551e2421541ff0928205bf419745012"
condition:
    ($a0 and $a1)
}