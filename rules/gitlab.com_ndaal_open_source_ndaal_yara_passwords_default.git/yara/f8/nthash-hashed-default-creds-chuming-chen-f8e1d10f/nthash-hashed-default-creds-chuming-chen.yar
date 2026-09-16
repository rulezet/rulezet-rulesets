rule nthash_hashed_default_creds_chuming_chen
{
    meta:
        id = "12MvAkQJ4gb5dZOXd3rqmP"
        fingerprint = "21a4e604ac64f3630f8a2b6e6684cd33a595fb23882fb185cc3be194cc5543ea"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for chuming_chen."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0110adc3eadbdcedbfa8496e6f6df5a0"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}